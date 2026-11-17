package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/md2k/subnet-tunnel/internal/config"
	"github.com/md2k/subnet-tunnel/internal/importer"
)

func newImportCmd(g *globalOpts) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Turn another tool's settings into a subtun profile",
	}
	cmd.AddCommand(newImportSSHuttleCmd(g))
	return cmd
}

func newImportSSHuttleCmd(g *globalOpts) *cobra.Command {
	var name, pod, namespace, kubeContext, container string
	var write bool
	cmd := &cobra.Command{
		Use:   "sshuttle FILE",
		Short: "Turn an sshuttle options file into a named subtun profile",
		Long: `Read an sshuttle options file (the @file format: one argument per line, as
used with "sshuttle @FILE") and make a subtun profile named --name from it:
printed as a config file, or with --write added to your config file (the
one --config, $SUBTUN_CONFIG or the default names), keeping its comments and
other profiles; the old file is kept as .bak.

Subnets and -x/--exclude become routes and excludes (redundant ones are
dropped, 0/0 becomes a full tunnel); --dns-domains patterns of the form
.*.suffix become DNS domains, other patterns regular expressions; --dns-to
becomes the DNS fallback, --ns-hosts the captured DNS servers; plain --dns
sends every name through the tunnel. Options subtun doesn't need or have are
listed in comments at the top, with what was dropped as redundant.

The target comes from sshuttle's SSH remote (-r, with -i, -J, -p and -l from
its --ssh-cmd; a password is left out: subtun logs in with keys or the SSH
agent). --k8s or --docker give an existing pod or container instead. Without
any of them the target is a placeholder to fill in (and --write refuses).`,
		Example: `  subtun import sshuttle work.conf --name work --k8s debug -n tools --context dev --write
  subtun import sshuttle work.conf --name work > work.yaml    # review first`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !config.ValidProfileName(name) {
				return fmt.Errorf("profile name %q: lowercase letters, digits, '.', '_' and '-'", name)
			}
			if pod != "" && container != "" {
				return errors.New("give --k8s or --docker, not both")
			}
			f, err := os.Open(args[0])
			if err != nil {
				return err
			}
			defer f.Close()
			p, err := importer.SSHuttle(f, os.ReadFile)
			if err != nil {
				return fmt.Errorf("%s: %w", args[0], err)
			}
			target := ""
			switch {
			case pod != "":
				parts := []string{"create: false", "name: " + quote(strings.TrimPrefix(pod, "pod/"))}
				if namespace != "" {
					parts = append([]string{"namespace: " + quote(namespace)}, parts...)
				}
				if kubeContext != "" {
					parts = append([]string{"context: " + quote(kubeContext)}, parts...)
				}
				target = "{k8s: {" + strings.Join(parts, ", ") + "}}"
			case container != "":
				target = "{docker: {create: false, name: " + quote(container) + "}}"
			case p.SSH != nil:
				target = p.SSH.Target()
			}
			if p.SSH != nil && (pod != "" || container != "") {
				p.Notes = append(p.Notes, "--remote "+p.SSH.Host+": replaced by the target given with --k8s/--docker")
			}
			errOut := cmd.ErrOrStderr()
			if write {
				if target == "" {
					return errors.New("--write needs a target: sshuttle's -r, or --k8s or --docker (subtun refuses a profile without one)")
				}
				path := g.config
				if path == "" {
					path = config.DefaultPath()
				}
				if err := writeProfile(path, name, func(indent string) string {
					return p.Entry(name, target, args[0], indent)
				}); err != nil {
					return err
				}
				fmt.Fprintf(errOut, "added profile %s to %s\n", name, path)
			} else if _, err := cmd.OutOrStdout().Write(p.YAML(name, target, args[0])); err != nil {
				return err
			}
			fmt.Fprintf(errOut, "imported %d routes, %d excludes, %d DNS domains, %d patterns; %d notes and %d dropped rules are in the comments at the top\n",
				len(p.Routes), len(p.Exclude), len(p.Domains), len(p.Patterns), len(p.Notes), len(p.Dropped))
			if target == "" {
				fmt.Fprintln(errOut, "set the target before adding this profile to your config: subtun refuses a profile without one (or rerun with --k8s/--docker)")
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&name, "name", "imported", "profile name")
	f.StringVar(&pod, "k8s", "", "target: this existing Kubernetes pod")
	f.StringVarP(&namespace, "namespace", "n", "", "the pod's namespace")
	f.StringVar(&kubeContext, "context", "", "kubeconfig context")
	f.StringVar(&container, "docker", "", "target: this existing Docker container")
	f.BoolVar(&write, "write", false, "add the profile to your config file instead of printing it")
	return cmd
}

// writeProfile adds a profile to the config file at path, creating the file
// if needed. The result must load, and the name must be new; the old file is
// kept as path.bak and replaced in one step.
func writeProfile(path, name string, entry func(indent string) string) error {
	old, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if len(old) > 0 {
		f, err := config.Parse(old, path)
		if err != nil {
			return fmt.Errorf("not touching %s, it doesn't load: %w", path, err)
		}
		if _, ok := f.Profiles[name]; ok {
			return fmt.Errorf("%s already has a profile %q; pick another --name", path, name)
		}
	}
	merged, err := importer.AddProfile(old, entry)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	f, err := config.Parse(merged, path)
	if err != nil {
		return fmt.Errorf("adding the profile would break %s, not writing it: %w", path, err)
	}
	if _, ok := f.Profiles[name]; !ok {
		return fmt.Errorf("adding the profile to %s failed, not writing it", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if len(old) > 0 {
		if err := os.WriteFile(path+".bak", old, 0o600); err != nil {
			return err
		}
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, merged, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
