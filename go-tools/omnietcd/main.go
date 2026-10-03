// omnietcd: a kubectl-style explorer AND editor for a self-hosted Omni's
// *encrypted* etcd data store.
//
// We hold the operator's PGP key, so we unwrap the AES-256 master key, decrypt
// every COSI resource, and can read/modify/delete any of them directly in etcd
//, bypassing Omni's API entirely (its RBAC, visibility filters and validation).
//
// Interactive REPL (arrow-key history + line editing via x/term), namespace and
// label selectors, and `edit` via $EDITOR (kubectl-style).
//
// Commands:
//
//	types                          list every resource type present (+counts)
//	get <type> [id] [-n ns] [-l k=v] [-o yaml]
//	edit <type> <id>               open $EDITOR, write the result back to etcd
//	set  <type> <id> <path> <val>  set a dotted spec path, write back to etcd
//	delete <type> <id>             delete the resource from etcd
//	apply -f <file>                create/update resources from a YAML file
//	raw  <type> <id>               show the etcd key + raw/decrypted bytes
//	grep <regex>                   search decrypted YAML across everything
//	namespace [ns] | output [table|yaml] | selector [k=v,...]   (REPL setters)
//	key | help | exit
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/cosi-project/runtime/pkg/keystorage"
	"github.com/cosi-project/runtime/pkg/resource"
	"github.com/cosi-project/runtime/pkg/resource/protobuf"
	"github.com/cosi-project/runtime/pkg/state/impl/store"
	"github.com/cosi-project/runtime/pkg/state/impl/store/compression"
	"github.com/cosi-project/runtime/pkg/state/impl/store/encryption"
	etcdstate "github.com/cosi-project/state-etcd/pkg/state/impl/etcd"
	"go.etcd.io/etcd/client/pkg/v3/transport"
	clientv3 "go.etcd.io/etcd/client/v3"
	yaml "go.yaml.in/yaml/v4"
	"golang.org/x/term"
	"k8s.io/kubectl/pkg/cmd/util/editor"

	"github.com/siderolabs/omni/internal/backend/runtime/keyprovider"

	_ "github.com/siderolabs/omni/client/pkg/omni/resources/auth"
	_ "github.com/siderolabs/omni/client/pkg/omni/resources/infra"
	_ "github.com/siderolabs/omni/client/pkg/omni/resources/k8s"
	_ "github.com/siderolabs/omni/client/pkg/omni/resources/oidc"
	_ "github.com/siderolabs/omni/client/pkg/omni/resources/omni"
	_ "github.com/siderolabs/omni/client/pkg/omni/resources/siderolink"
	_ "github.com/siderolabs/omni/client/pkg/omni/resources/system"
	_ "github.com/siderolabs/omni/client/pkg/omni/resources/virtual"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

type entry struct {
	res resource.Resource
	key []byte // exact etcd key
	val []byte // raw (encrypted) etcd value
}

type explorer struct {
	ctx       context.Context
	cli       *clientv3.Client
	core      *etcdstate.State
	marshaler store.Marshaler
	cipher    *encryption.Cipher
	all       []entry
	slot      string
	masterKey []byte
	undecoded int

	// REPL state / "setters"
	namespace string // "" = all
	output    string // table|yaml
	selector  map[string]string
}

func run() error {
	var (
		accountID = env("ACCOUNT_ID", "287cfd52-735b-4dbf-bfc8-c47593e09c3b")
		etcdEP    = env("ETCD_ENDPOINT", "https://127.0.0.1:2379")
		caFile    = env("ETCD_CA", "etcd-certs/ca.crt")
		certFile  = env("ETCD_CERT", "etcd-certs/client.crt")
		keyFile   = env("ETCD_KEY", "etcd-certs/client.key")
		privKey   = env("OMNI_PRIVATE_KEY", "keys/omni.asc")
	)

	ctx := context.Background()

	tlsInfo := transport.TLSInfo{CertFile: certFile, KeyFile: keyFile, TrustedCAFile: caFile}
	tlsCfg, err := tlsInfo.ClientConfig()
	if err != nil {
		return err
	}
	cli, err := clientv3.New(clientv3.Config{Endpoints: []string{etcdEP}, TLS: tlsCfg, DialTimeout: 5 * time.Second})
	if err != nil {
		return err
	}
	defer cli.Close()

	privArmored, err := os.ReadFile(privKey)
	if err != nil {
		return err
	}
	hexHash := fmt.Sprintf("%x", sha256.Sum256([]byte(accountID)))
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	ksResp, err := cli.Get(cctx, "keystore-omni/record-store/"+hexHash)
	cancel()
	if err != nil {
		return err
	}
	if len(ksResp.Kvs) == 0 {
		return fmt.Errorf("keystore record not found")
	}
	ks := &keystorage.KeyStorage{}
	if err := ks.UnmarshalBinary(ksResp.Kvs[0].Value); err != nil {
		return err
	}
	slot, err := keyprovider.GetIdentityString(string(privArmored))
	if err != nil {
		return err
	}
	masterKey, err := ks.GetMasterKey(slot, string(privArmored))
	if err != nil {
		return err
	}

	cipher := encryption.NewCipher(encryption.KeyProviderFunc(func() ([]byte, error) { return masterKey, nil }))
	marshaler := encryption.NewMarshaler(
		compression.NewMarshaler(store.ProtobufMarshaler{}, compression.ZStd(), 2048),
		cipher,
	)
	salt := sha256.Sum256([]byte(accountID))
	prefix := fmt.Sprintf("/omni/%s", url.PathEscape(accountID))
	core := etcdstate.NewState(cli, marshaler, etcdstate.WithKeyPrefix(prefix), etcdstate.WithSalt(salt[:]))

	ex := &explorer{
		ctx: ctx, cli: cli, core: core, marshaler: marshaler, cipher: cipher,
		slot: slot, masterKey: masterKey, namespace: "", output: "table", selector: map[string]string{},
	}
	if err := ex.load(prefix); err != nil {
		return err
	}

	args := os.Args[1:]
	if len(args) == 0 || args[0] == "repl" {
		ex.repl()
		return nil
	}
	ex.dispatch(args)
	return nil
}

func (e *explorer) load(prefix string) error {
	cctx, cancel := context.WithTimeout(e.ctx, 30*time.Second)
	defer cancel()
	resp, err := e.cli.Get(cctx, prefix+"/", clientv3.WithPrefix())
	if err != nil {
		return err
	}
	e.all = e.all[:0]
	e.undecoded = 0
	for _, kv := range resp.Kvs {
		r, err := e.marshaler.UnmarshalResource(kv.Value)
		if err != nil {
			e.undecoded++
			continue
		}
		e.all = append(e.all, entry{res: r, key: append([]byte(nil), kv.Key...), val: append([]byte(nil), kv.Value...)})
	}
	sort.SliceStable(e.all, func(i, j int) bool {
		a, b := e.all[i].res.Metadata(), e.all[j].res.Metadata()
		if a.Type() != b.Type() {
			return a.Type() < b.Type()
		}
		return a.ID() < b.ID()
	})
	return nil
}

// ------------------------------------------------------------------ dispatch
func (e *explorer) dispatch(args []string) {
	if len(args) == 0 {
		return
	}
	switch args[0] {
	case "types", "api-resources", "ls":
		e.cmdTypes()
	case "get":
		e.cmdGet(args[1:])
	case "edit":
		e.cmdEdit(args[1:])
	case "set":
		e.cmdSet(args[1:])
	case "delete", "rm":
		e.cmdDelete(args[1:])
	case "apply":
		e.cmdApply(args[1:])
	case "raw":
		e.cmdRaw(args[1:])
	case "grep", "search":
		if len(args) < 2 {
			fmt.Println("usage: grep <regex>")
			return
		}
		e.cmdGrep(strings.Join(args[1:], " "))
	case "namespace", "ns":
		e.cmdNamespace(args[1:])
	case "output", "o":
		if len(args) > 1 {
			e.output = args[1]
		}
		fmt.Println("output:", e.output)
	case "selector", "labels", "l":
		e.cmdSelector(args[1:])
	case "reload":
		if err := e.load(fmt.Sprintf("/omni/%s", e.accountPrefix())); err != nil {
			fmt.Println("reload error:", err)
		} else {
			fmt.Printf("reloaded %d resources\n", len(e.all))
		}
	case "complete": // debug: show what <Tab> would do for the rest of the line
		line := strings.Join(args[1:], " ")
		nl, _, listed, ok := e.computeCompletion(line, len(line))
		fmt.Printf("ok=%v\nline => %q\n", ok, nl)
		if len(listed) > 0 {
			fmt.Println("candidates:", strings.Join(listed, " "))
		}
	case "key", "masterkey":
		fmt.Printf("slot       : %s\nmaster key : %x\n", e.slot, e.masterKey)
	case "help", "?":
		e.help()
	default:
		fmt.Printf("unknown command %q (try help)\n", args[0])
	}
}

func (e *explorer) accountPrefix() string {
	// the key prefix is /omni/<acct>; recover <acct> from any loaded key
	if len(e.all) > 0 {
		parts := strings.SplitN(string(e.all[0].key), "/", 4)
		if len(parts) >= 3 {
			return parts[2]
		}
	}
	return env("ACCOUNT_ID", "287cfd52-735b-4dbf-bfc8-c47593e09c3b")
}

func (e *explorer) help() {
	fmt.Print(`commands:
  types                              list every resource type present (+counts)
  get <type> [id] [-n ns] [-l k=v] [-o yaml|-y]
  edit <type> <id>                   open $EDITOR, write the result back to etcd
  set <type> <id> <dotted.path> <value>   set one spec field, write back
  delete <type> <id>                 delete the resource from etcd
  apply -f <file.yaml>               create/update resources from YAML
  raw <type> <id>                    etcd key + raw & decrypted bytes
  grep <regex>                       search decrypted YAML across everything
  namespace [ns]                     show/set the active namespace filter ('' = all)
  selector [k=v,...]                 show/set the active label selector
  output [table|yaml]                show/set default output format
  reload                             re-read the store from etcd
  key                                show recovered master key + PGP slot
  help | exit
`)
}

// ------------------------------------------------------------------ queries
func (e *explorer) match(typeSub, idSub string) []entry {
	var out []entry
	for _, en := range e.all {
		md := en.res.Metadata()
		if !strings.Contains(strings.ToLower(md.Type()), strings.ToLower(typeSub)) {
			continue
		}
		if idSub != "" && !strings.Contains(strings.ToLower(md.ID()), strings.ToLower(idSub)) {
			continue
		}
		if e.namespace != "" && md.Namespace() != e.namespace {
			continue
		}
		if !labelsMatch(md.Labels().Raw(), e.selector) {
			continue
		}
		out = append(out, en)
	}
	return out
}

func labelsMatch(have, want map[string]string) bool {
	for k, v := range want {
		hv, ok := have[k]
		if !ok || (v != "" && hv != v) {
			return false
		}
	}
	return true
}

func (e *explorer) cmdTypes() {
	type agg struct {
		count int
		ns    map[string]struct{}
	}
	m := map[string]*agg{}
	for _, en := range e.all {
		md := en.res.Metadata()
		if e.namespace != "" && md.Namespace() != e.namespace {
			continue
		}
		if !labelsMatch(md.Labels().Raw(), e.selector) {
			continue
		}
		t := md.Type()
		if m[t] == nil {
			m[t] = &agg{ns: map[string]struct{}{}}
		}
		m[t].count++
		m[t].ns[md.Namespace()] = struct{}{}
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "COUNT\tTYPE\tNAMESPACE(S)")
	for _, k := range keys {
		var nss []string
		for n := range m[k].ns {
			nss = append(nss, n)
		}
		sort.Strings(nss)
		fmt.Fprintf(w, "%d\t%s\t%s\n", m[k].count, k, strings.Join(nss, ","))
	}
	w.Flush()
	fmt.Printf("\n%d types (filters: ns=%q selector=%v), %d undecodable non-resource keys\n",
		len(keys), e.namespace, e.selector, e.undecoded)
}

func (e *explorer) cmdGet(args []string) {
	typeSub, idSub, asYAML, nsOverride, selOverride := "", "", e.output == "yaml", "", map[string]string(nil)
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-y" || a == "--yaml":
			asYAML = true
		case a == "-o" && i+1 < len(args):
			asYAML = args[i+1] == "yaml" || args[i+1] == "y"
			i++
		case a == "-n" && i+1 < len(args):
			nsOverride = args[i+1]
			i++
		case a == "-l" && i+1 < len(args):
			selOverride = parseSelector(args[i+1])
			i++
		default:
			pos = append(pos, a)
		}
	}
	if len(pos) == 0 {
		fmt.Println("usage: get <type> [id] [-n ns] [-l k=v] [-o yaml]")
		return
	}
	typeSub = pos[0]
	if len(pos) > 1 {
		idSub = pos[1]
		asYAML = true
	}
	// temporary filter overrides
	savedNS, savedSel := e.namespace, e.selector
	if nsOverride != "" {
		e.namespace = nsOverride
	}
	if selOverride != nil {
		e.selector = selOverride
	}
	matches := e.match(typeSub, idSub)
	e.namespace, e.selector = savedNS, savedSel

	if len(matches) == 0 {
		fmt.Printf("no resources match type~=%q id~=%q (ns=%q)\n", typeSub, idSub, nsOverride)
		return
	}
	if asYAML {
		e.printYAML(matches)
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "NAMESPACE\tTYPE\tID\tVER\tPHASE\tLABELS")
	for _, en := range matches {
		md := en.res.Metadata()
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			md.Namespace(), md.Type(), md.ID(), md.Version(), md.Phase(), fmtLabels(md.Labels().Raw()))
	}
	w.Flush()
	fmt.Printf("\n%d resource(s). add an id or -o yaml for full specs.\n", len(matches))
}

func (e *explorer) printYAML(matches []entry) {
	enc := yaml.NewEncoder(os.Stdout)
	for i, en := range matches {
		if i > 0 {
			fmt.Println("---")
		}
		out, err := resource.MarshalYAML(en.res)
		if err != nil {
			fmt.Printf("# marshal error: %v\n", err)
			continue
		}
		_ = enc.Encode(out)
	}
	enc.Close()
}

// ------------------------------------------------------------------ mutation
// one picks exactly one resource for mutating commands.
func (e *explorer) one(args []string) (entry, bool) {
	if len(args) < 2 {
		fmt.Println("need <type> <id>")
		return entry{}, false
	}
	m := e.match(args[0], args[1])
	if len(m) == 0 {
		fmt.Println("no match")
		return entry{}, false
	}
	// prefer exact id match
	for _, en := range m {
		if strings.EqualFold(en.res.Metadata().ID(), args[1]) {
			return en, true
		}
	}
	if len(m) > 1 {
		fmt.Printf("ambiguous (%d matches); be more specific:\n", len(m))
		for _, en := range m {
			fmt.Printf("  %s / %s\n", en.res.Metadata().Type(), en.res.Metadata().ID())
		}
		return entry{}, false
	}
	return m[0], true
}

// writeBack re-encrypts res with the exact master key and PUTs it to its etcd key.
// This bypasses version/owner/finalizer checks, we own the data store.
func (e *explorer) writeBack(key []byte, res resource.Resource) error {
	data, err := e.marshaler.MarshalResource(res)
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(e.ctx, 15*time.Second)
	defer cancel()
	_, err = e.cli.Put(cctx, string(key), string(data))
	return err
}

func (e *explorer) cmdEdit(args []string) {
	en, ok := e.one(args)
	if !ok {
		return
	}
	out, err := resource.MarshalYAML(en.res)
	if err != nil {
		fmt.Println("marshal:", err)
		return
	}
	buf, _ := yaml.Marshal(out)

	ed := editor.NewDefaultEditor([]string{"OMNI_EDITOR", "TALOS_EDITOR", "EDITOR"})
	edited, path, err := ed.LaunchTempFile("omnietcd-edit-", ".yaml", bytes.NewReader(buf))
	if path != "" {
		defer os.Remove(path)
	}
	if err != nil {
		fmt.Println("editor:", err)
		return
	}
	if bytes.Equal(bytes.TrimSpace(edited), bytes.TrimSpace(buf)) {
		fmt.Println("no changes.")
		return
	}
	res, err := decodeOne(edited)
	if err != nil {
		fmt.Println("parse edited yaml:", err)
		return
	}
	if err := e.writeBack(en.key, res); err != nil {
		fmt.Println("write back:", err)
		return
	}
	fmt.Printf("updated %s/%s in etcd\n", res.Metadata().Type(), res.Metadata().ID())
	_ = e.load(fmt.Sprintf("/omni/%s", e.accountPrefix()))
}

func (e *explorer) cmdSet(args []string) {
	if len(args) < 4 {
		fmt.Println("usage: set <type> <id> <dotted.path> <value>")
		return
	}
	en, ok := e.one(args[:2])
	if !ok {
		return
	}
	path, val := args[2], strings.Join(args[3:], " ")

	out, err := resource.MarshalYAML(en.res)
	if err != nil {
		fmt.Println("marshal:", err)
		return
	}
	buf, _ := yaml.Marshal(out)
	var doc map[string]any
	if err := yaml.Unmarshal(buf, &doc); err != nil {
		fmt.Println("yaml:", err)
		return
	}
	spec, _ := doc["spec"].(map[string]any)
	if spec == nil {
		fmt.Println("resource has no spec")
		return
	}
	if err := setDotted(spec, strings.Split(path, "."), val); err != nil {
		fmt.Println("set:", err)
		return
	}
	newBuf, _ := yaml.Marshal(doc)
	res, err := decodeOne(newBuf)
	if err != nil {
		fmt.Println("re-decode:", err)
		return
	}
	if err := e.writeBack(en.key, res); err != nil {
		fmt.Println("write back:", err)
		return
	}
	fmt.Printf("set spec.%s=%q on %s/%s\n", path, val, res.Metadata().Type(), res.Metadata().ID())
	_ = e.load(fmt.Sprintf("/omni/%s", e.accountPrefix()))
}

func (e *explorer) cmdDelete(args []string) {
	en, ok := e.one(args)
	if !ok {
		return
	}
	cctx, cancel := context.WithTimeout(e.ctx, 15*time.Second)
	defer cancel()
	if _, err := e.cli.Delete(cctx, string(en.key)); err != nil {
		fmt.Println("delete:", err)
		return
	}
	fmt.Printf("deleted %s/%s from etcd\n", en.res.Metadata().Type(), en.res.Metadata().ID())
	_ = e.load(fmt.Sprintf("/omni/%s", e.accountPrefix()))
}

func (e *explorer) cmdApply(args []string) {
	var file string
	for i := 0; i < len(args); i++ {
		if (args[i] == "-f" || args[i] == "--file") && i+1 < len(args) {
			file = args[i+1]
			i++
		}
	}
	if file == "" {
		fmt.Println("usage: apply -f <file.yaml>")
		return
	}
	data, err := os.ReadFile(file)
	if err != nil {
		fmt.Println("read:", err)
		return
	}
	resources, err := decodeAll(data)
	if err != nil {
		fmt.Println("parse:", err)
		return
	}
	for _, res := range resources {
		// find existing etcd key for this ns/type/id
		var key []byte
		for _, en := range e.all {
			md := en.res.Metadata()
			if md.Namespace() == res.Metadata().Namespace() && md.Type() == res.Metadata().Type() && md.ID() == res.Metadata().ID() {
				key = en.key
				break
			}
		}
		if key != nil {
			if err := e.writeBack(key, res); err != nil {
				fmt.Printf("update %s/%s: %v\n", res.Metadata().Type(), res.Metadata().ID(), err)
				continue
			}
			fmt.Printf("updated %s/%s\n", res.Metadata().Type(), res.Metadata().ID())
		} else {
			cctx, cancel := context.WithTimeout(e.ctx, 15*time.Second)
			err := e.core.Create(cctx, res)
			cancel()
			if err != nil {
				fmt.Printf("create %s/%s: %v\n", res.Metadata().Type(), res.Metadata().ID(), err)
				continue
			}
			fmt.Printf("created %s/%s\n", res.Metadata().Type(), res.Metadata().ID())
		}
	}
	_ = e.load(fmt.Sprintf("/omni/%s", e.accountPrefix()))
}

func (e *explorer) cmdRaw(args []string) {
	en, ok := e.one(args)
	if !ok {
		return
	}
	fmt.Printf("etcd key   : %s\n", string(en.key))
	fmt.Printf("raw value  : %d bytes, prefix %x...\n", len(en.val), en.val[:min(16, len(en.val))])
	plain, err := e.cipher.Decrypt(en.val)
	if err != nil {
		fmt.Println("decrypt:", err)
		return
	}
	note := "uncompressed protobuf"
	if len(plain) > 1 && plain[0] == 0x00 {
		note = fmt.Sprintf("zstd-framed (compressor id %d)", plain[1])
	}
	fmt.Printf("decrypted  : %d bytes (%s)\n", len(plain), note)
	fmt.Printf("plaintext prefix %x...\n", plain[:min(32, len(plain))])
}

func (e *explorer) cmdGrep(pat string) {
	re, err := regexp.Compile("(?i)" + pat)
	if err != nil {
		fmt.Println("bad regex:", err)
		return
	}
	hits := 0
	for _, en := range e.all {
		out, err := resource.MarshalYAML(en.res)
		if err != nil {
			continue
		}
		b, _ := yaml.Marshal(out)
		var lines []string
		for _, ln := range strings.Split(string(b), "\n") {
			if re.MatchString(ln) {
				lines = append(lines, strings.TrimSpace(ln))
			}
		}
		if len(lines) > 0 {
			hits++
			fmt.Printf("== %s / %s ==\n", en.res.Metadata().Type(), en.res.Metadata().ID())
			for _, ln := range lines {
				fmt.Printf("  %s\n", ln)
			}
		}
	}
	fmt.Printf("\n%d resource(s) matched /%s/\n", hits, pat)
}

func (e *explorer) cmdNamespace(args []string) {
	if len(args) == 0 {
		fmt.Printf("namespace filter: %q\n", e.namespace)
		seen := map[string]int{}
		for _, en := range e.all {
			seen[en.res.Metadata().Namespace()]++
		}
		var nss []string
		for n := range seen {
			nss = append(nss, n)
		}
		sort.Strings(nss)
		fmt.Println("available namespaces:")
		for _, n := range nss {
			fmt.Printf("  %-12s %d resources\n", n, seen[n])
		}
		return
	}
	if args[0] == "all" || args[0] == "-" || args[0] == `""` {
		e.namespace = ""
	} else {
		e.namespace = args[0]
	}
	fmt.Printf("namespace filter set to %q\n", e.namespace)
}

func (e *explorer) cmdSelector(args []string) {
	if len(args) == 0 {
		fmt.Printf("selector: %v\n", e.selector)
		return
	}
	if args[0] == "clear" || args[0] == "-" {
		e.selector = map[string]string{}
	} else {
		e.selector = parseSelector(args[0])
	}
	fmt.Printf("selector set to %v\n", e.selector)
}

// ------------------------------------------------------------------ REPL
func (e *explorer) prompt() string {
	ns := e.namespace
	if ns == "" {
		ns = "*"
	}
	return fmt.Sprintf("omni[%s]> ", ns)
}

func (e *explorer) repl() {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		e.replPlain()
		return
	}
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		e.replPlain()
		return
	}
	t := term.NewTerminal(struct {
		io.Reader
		io.Writer
	}{os.Stdin, os.Stdout}, e.prompt())
	t.AutoCompleteCallback = func(line string, pos int, key rune) (string, int, bool) {
		if key != '\t' {
			return "", 0, false
		}
		newLine, newPos, listed, ok := e.computeCompletion(line, pos)
		if len(listed) > 0 {
			// print candidates above a freshly-redrawn prompt (raw mode -> \r\n)
			fmt.Fprint(t, "\r\n"+formatColumns(listed)+"\r\n")
		}
		return newLine, newPos, ok
	}
	// keep raw only during ReadLine
	term.Restore(fd, oldState)

	fmt.Printf("omni etcd explorer, %d resources decrypted (%d undecodable). ↑/↓ = history, Tab = complete.\n", len(e.all), e.undecoded)
	fmt.Println(`type "help" for commands, "exit" to quit.`)

	for {
		t.SetPrompt(e.prompt())
		st, _ := term.MakeRaw(fd)
		line, err := t.ReadLine()
		term.Restore(fd, st)
		if err != nil { // EOF / Ctrl-D / Ctrl-C
			fmt.Println()
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line == "exit" || line == "quit" {
			return
		}
		e.dispatch(fields(line))
	}
}

func (e *explorer) replPlain() {
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	readLine := func() (string, bool) {
		for {
			if i := bytes.IndexByte(buf, '\n'); i >= 0 {
				ln := string(buf[:i])
				buf = buf[i+1:]
				return ln, true
			}
			n, err := os.Stdin.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
			}
			if err != nil {
				if len(buf) > 0 {
					ln := string(buf)
					buf = nil
					return ln, true
				}
				return "", false
			}
		}
	}
	for {
		ln, ok := readLine()
		if !ok {
			return
		}
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		if ln == "exit" || ln == "quit" {
			return
		}
		e.dispatch(fields(ln))
	}
}

// ------------------------------------------------------------------ tab completion
var replCommands = []string{
	"types", "get", "edit", "set", "delete", "apply", "raw", "grep",
	"namespace", "selector", "output", "reload", "key", "help", "exit",
}

// commands whose 1st arg is a resource type and 2nd arg is an id.
func cmdTakesTypeID(cmd string) (typeArg, idArg bool) {
	switch cmd {
	case "get", "edit", "set", "delete", "rm", "raw":
		return true, true
	}
	return false, false
}

// computeCompletion returns the completed line, new cursor pos, any candidate
// list to display, and whether a completion was produced.
func (e *explorer) computeCompletion(line string, pos int) (string, int, []string, bool) {
	if pos != len(line) { // only complete at end of line
		return "", 0, nil, false
	}
	trailingSpace := strings.HasSuffix(line, " ")
	toks := strings.Fields(line)

	// what token index are we completing, and its current prefix?
	var prefix string
	var argIdx int // 0 = command, 1 = first arg, ...
	if trailingSpace {
		argIdx = len(toks)
		prefix = ""
	} else if len(toks) == 0 {
		argIdx, prefix = 0, ""
	} else {
		argIdx = len(toks) - 1
		prefix = toks[len(toks)-1]
	}

	var candidates []string
	switch {
	case argIdx == 0:
		candidates = replCommands
	default:
		cmd := toks[0]
		typeArg, idArg := cmdTakesTypeID(cmd)
		switch {
		case typeArg && argIdx == 1:
			candidates = e.distinctTypes()
		case idArg && argIdx == 2:
			candidates = e.idsForType(toks[1])
		case cmd == "namespace" || cmd == "ns":
			candidates = e.namespaceNames()
		default:
			return "", 0, nil, false
		}
	}

	chosen, listed, ok := completeAgainst(prefix, candidates)
	if !ok {
		return "", 0, nil, false
	}
	base := line
	if !trailingSpace && len(toks) > 0 {
		base = line[:len(line)-len(prefix)]
	}
	newLine := base + chosen
	if len(listed) == 0 { // unique completion -> add a space
		newLine += " "
	}
	return newLine, len(newLine), listed, true
}

// completeAgainst matches prefix against candidates (case-insensitive prefix,
// falling back to substring) and returns the text to insert plus, when the
// result is ambiguous, the list of matches to display.
func completeAgainst(prefix string, candidates []string) (string, []string, bool) {
	lp := strings.ToLower(prefix)

	var pre, sub []string
	for _, c := range candidates {
		lc := strings.ToLower(c)
		if strings.HasPrefix(lc, lp) {
			pre = append(pre, c)
		} else if lp != "" && strings.Contains(lc, lp) {
			sub = append(sub, c)
		}
	}

	matches, isPrefix := pre, true
	if len(matches) == 0 {
		matches, isPrefix = sub, false
	}
	switch len(matches) {
	case 0:
		return "", nil, false
	case 1:
		return matches[0], nil, true
	}
	sort.Strings(matches)
	if isPrefix {
		if lcp := longestCommonPrefix(matches); len(lcp) > len(prefix) {
			return lcp, matches, true // extend + list
		}
	}
	return prefix, matches, true // keep prefix, just list
}

func longestCommonPrefix(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	p := ss[0]
	for _, s := range ss[1:] {
		for !strings.HasPrefix(strings.ToLower(s), strings.ToLower(p)) {
			p = p[:len(p)-1]
			if p == "" {
				return ""
			}
		}
	}
	return p
}

func (e *explorer) distinctTypes() []string {
	seen := map[string]struct{}{}
	var out []string
	for _, en := range e.all {
		t := en.res.Metadata().Type()
		if _, ok := seen[t]; !ok {
			seen[t] = struct{}{}
			out = append(out, t)
		}
	}
	return out
}

func (e *explorer) idsForType(typeTok string) []string {
	lt := strings.ToLower(typeTok)
	seen := map[string]struct{}{}
	var out []string
	for _, en := range e.all {
		md := en.res.Metadata()
		if !strings.Contains(strings.ToLower(md.Type()), lt) {
			continue
		}
		if e.namespace != "" && md.Namespace() != e.namespace {
			continue
		}
		if _, ok := seen[md.ID()]; !ok {
			seen[md.ID()] = struct{}{}
			out = append(out, md.ID())
		}
	}
	return out
}

func (e *explorer) namespaceNames() []string {
	seen := map[string]struct{}{}
	var out []string
	for _, en := range e.all {
		n := en.res.Metadata().Namespace()
		if _, ok := seen[n]; !ok {
			seen[n] = struct{}{}
			out = append(out, n)
		}
	}
	return out
}

func formatColumns(items []string) string {
	sort.Strings(items)
	if len(items) <= 6 {
		return strings.Join(items, "   ")
	}
	var b strings.Builder
	for i, it := range items {
		if i > 0 {
			if i%3 == 0 {
				b.WriteString("\r\n")
			} else {
				b.WriteString("   ")
			}
		}
		b.WriteString(it)
	}
	return b.String()
}

// ------------------------------------------------------------------ helpers
func decodeOne(data []byte) (resource.Resource, error) {
	rs, err := decodeAll(data)
	if err != nil {
		return nil, err
	}
	if len(rs) == 0 {
		return nil, fmt.Errorf("no resource in document")
	}
	return rs[0], nil
}

func decodeAll(data []byte) ([]resource.Resource, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var out []resource.Resource
	for {
		var r protobuf.YAMLResource
		err := dec.Decode(&r)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		out = append(out, r.Resource())
	}
	return out, nil
}

func setDotted(m map[string]any, path []string, val string) error {
	for i, p := range path {
		if i == len(path)-1 {
			m[p] = coerce(val)
			return nil
		}
		nxt, ok := m[p].(map[string]any)
		if !ok {
			nxt = map[string]any{}
			m[p] = nxt
		}
		m = nxt
	}
	return nil
}

func coerce(v string) any {
	switch v {
	case "true":
		return true
	case "false":
		return false
	case "null", "~":
		return nil
	}
	return v
}

func parseSelector(s string) map[string]string {
	out := map[string]string{}
	for _, kv := range strings.Split(s, ",") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		if i := strings.IndexAny(kv, "="); i >= 0 {
			out[strings.TrimSpace(kv[:i])] = strings.TrimSpace(kv[i+1:])
		} else {
			out[kv] = ""
		}
	}
	return out
}

func fmtLabels(m map[string]string) string {
	if len(m) == 0 {
		return "-"
	}
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		if m[k] == "" {
			parts = append(parts, k)
		} else {
			parts = append(parts, k+"="+m[k])
		}
	}
	return strings.Join(parts, ",")
}

func fields(s string) []string {
	var out []string
	var cur strings.Builder
	inQ := false
	for _, r := range s {
		switch {
		case r == '"':
			inQ = !inQ
		case r == ' ' && !inQ:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
