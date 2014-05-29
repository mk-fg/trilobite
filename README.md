trilobite: iptables wrapper for easy management of dual-stack (ipv4/ipv6) firewall configuration
--------------------

Yet another iptables wrapper, aiming to keep simple, clear and minimalistic
state of dual-stack firewall in a
[DRY](https://en.wikipedia.org/wiki/Don%27t_repeat_yourself) yaml configuration
file, featuring as little differences from lower-level (iptables) syntax as
possible, atomic updates, plain diffs of current state vs config, ruleset
backups and various fallbacks to make sure I don't accidentally lock myself out
of the machine.


### Operation

YAML config gets parsed into two iptables-save/restore dumps (one for IPv4,
another for IPv6). Each line gets expanded w/ appropriate modules, chain name
and jump-action. Script decides which rules should be omitted in v4/v6 dump by
looking at IP format and optional -v4/-v6 flag.

After that, it pulls the old tables via iptables-save to tmp buffer and tries to
feed the new ones to iptables-restore, which will atomically apply all new rules
if there are no errors in any of them.

If new tables got applied, it dumps the them again, comparing then to the old
dump to see if there are any diffirences (aside from comments and packet
counters).

Then old-vs-new diff can be generated with --summary option, backups will be
made/rotated and, unless --no-revert option is specified, "at" will be used to
schedule rules' revert in a few minutes, which should be disabled manually, if
ssh (or whatever access) wasn't accidentally blocked by the new rules.

Code that does all this is a bag of hacks in huge loops piled on over time.



### Configuration


##### Chains, policies and generic rules

Should be pretty intuitive from the yaml example, otherwise some parts are
explained below.

If there's no explicit --state spec in rule, ALL rules will get "-m state
--state NEW". Basically, that means that all such rules act on per-connection
(as opposed to per-packet) basis by default.
That can be disabled via "stateful" configuration switch.

Start of the rule definitions section and filter table init - you can actually
replace chain definition, like "input:" by "input/-" to set policy to DROP, or
"somechain/x" for REJECT, "/+" for ACCEPT, same as for rules.

There are also special "somechain/4" and "somechain/6" policy specs, which mean
"ACCEPT for v4, DROP for v6" and the reverse thing respectively.

	tablez:
		filter:
			input:
				- --state RELATED,ESTABLISHED
				- -v4 -p icmp
				- -v6 -p icmpv6
			forward:
			output:

Three rules in input, first in this chain, will be same as...

	$IPT4 -t filter -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
	$IPT6 -t filter -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
	$IPT4 -t filter -A INPUT -p icmp -j ACCEPT
	$IPT6 -t filter -A INPUT -p icmp6 -j ACCEPT

...generally-used bash code will produce.

Note the "-v4" and "-v6" switches and that "-j ACCEPT" is added by default to
non-empty rules (which are special, and mean "-j DROP") if no "-", "x", "<" or
"|" specified in the end.

Empty chain definitions (as with "output" here) are fine, too.

	minions_in:
		- -i vde -s 2001:470:1f0b:11de::20/124
		- <

Custom chain definition. First line will go to ipv6 table only, second is the
special magic syntax (one of a few) for "-j RETURN", which will produce
passthrough chain in ipv4 and a check for ipv6.

	- -i lan -s 192.168.0.10 --mac-source 00:11:6b:28:7f:68 # wlan.v4c

Won't need "-m mac", since it's quite obvious that it should be present here,
and it will be added to the final rule. Note the comment - it's valid yaml
comment, and won't be parsed.

	# Azureus to coercion
	- -p tcp/udp -d 192.168.0.13 --dport 28637
	- -p udp -d 192.168.0.13 --dport 28638

	# Outgoing p2p traffic
	- -p tcp/udp --gid-owner p2p/transmission/mldonkey

Any number of "-p proto1/proto2..." will be expanded as multiple rules, one for
each protocol, as with tcp/udp in this case.
Same goes for other convenience expansions - "--sport/dport" (common in
stateless rulesets/chains/protos), "--uid-owner a/b/c", etc.

Basically it's all accomplised by a bunch of regexes, ran over rules:

	extend_modules = {
		'--mac-source': 'mac',
		'--state': 'state',
		'--(src|dst)-range': 'iprange',
		'--[sd]port\s+(\S+,)+\S+': 'multiport',
		'--match-set': 'set',
		'--pkt-type': 'pkttype',
		'--[ug]id-owner': 'owner',
		...

	extend_duplicate = [
		r'(?<=-p\s)(?P<args>(\w+/)+\w+)',
		r'(?<=--)(?P<args>[sd]port/[sd]port)',
		r'(?<=--[sd]port\s)(?P<args>(\w+/)+\w+)',
		r'(?<=--[ug]id-owner\s)(?P<args>(\w+/)+\w+)',
		...

See beginning of the script for the up-to-date list of these.

	- -p tcp -d 2001:470:1f0a:11de::2
	# Cut the rest
	-

Yep, last one is an empty rule, which will be interpreted as "-" - "-j DROP".

	- +
	- x

Briefly described above syntax magic - expands to "-j ACCEPT" and "-j REJECT"
respectively.


##### Service rules

	svc:

		loopback:
			input-lo: +
			output-lo: +

Start of "services" section.

Here rules can be grouped on per-service (or purpose) basis by specific
service. Service name/purpose will go into the resulting dump as a comment.

Service rules get added to the specified chains in order they appear in the
configuration file. Again, it's probably more obvious in example config.

"input-lo" here is "<chain>-<interface>" specification - it's valid for
input/output chains, and will add "-i interface" or "-o interface" to each rule
specified inside.

"+" is just a yaml string (expands to "-j ACCEPT"), instead of dict ("name:
...") or list ("- ...") notation, seen above.
String will just be parsed as one rule, so there's no need to make a lists for
one-liners.

Result of these should be roughly this:

	$IPT4 -A INPUT -i lo -m state --state NEW -j ACCEPT
	$IPT6 -A INPUT -i lo -m state --state NEW -j ACCEPT
	$IPT4 -A OUTPUT -o lo -m state --state NEW -j ACCEPT
	$IPT6 -A OUTPUT -o lo -m state --state NEW -j ACCEPT

"-j action/chain" works as in vanilla tables:

		core:
			input-lan: -j core_in
			output-lan: -j core_out

Just an svc name with a simple allow-all ipv6 rule:

		6to4_forwarding: -v6 -i tot

Such rules will go into INPUT chain by default.

		telenet_segnet_drop:
			input-ppp2:
				- -s 90.157.91.0/24 -
				- -s 90.157.40.128/25 -
			output-ppp2:
				- -d 90.157.91.0/24 -
				- -d 90.157.40.128/25 -

Bunch of IPv4 DROP rules for ppp2 interface.

		ssh: -p tcp --dport ssh

Simple "open port" rule (for ssh on port 22, in this case), sufficient for 90%
of services.

		mail: -p tcp --dport smtp,pop3,imap,pop3s,imaps

"-m multiport" will be added here.

		intranet_connz_reject:
			input-ppp2:
				- -s 90.157.0.0/17 x
				- -s 87.224.128.0/17 x
				- -v4

All for ip4tables. Last one is "-j DROP".

		finish: x

Can be a last "reject-everything-else" rule.

There's also support for ipsets and some other modules. Check out the beginning
of the code for up2date expansion definitions.


##### Metrics

Only special syntax which is not translated to iptables at all atm is
"--metrics" switch:

		mcast: --pkt-type multicast --metrics media.packets
		...
		pulse: -s 192.168.0.163 -p tcp --dport 4712,4713 --metrics pulse.connz/media.packets

It builds a special file (location can be specified in config) with the "table
chain rule_number name" syntax, example:

	filter INPUT 8 media.packets
	filter INPUT 12 sshd.connz
	filter INPUT 13 media.packets
	filter INPUT 13 pulse.connz

...which can be used later with netfilter counters (think "iptables -L INPUT
-vn") to produce stats for specific types of traffic on a local machine.

Note that since 99% of tcp packets (all, except syn) are usually matched by some
"--state RELATED,ESTABLISHED" rule, "pulse" rule above will only count syn
packets (new connections), not the actual traffic.

It's to count connections' traffic as well, it's possible to use
"--metrics-track" magic, with following section in the config:

	metrics_conntrack:
		enabled: true
		table: filter
		chain: conn_metrics
		shift: 0

So a rule like this:

	pulse: -s 192.168.0.163 -p tcp --dport 4712,4713 --metrics-track media.packets

Will be transformed into a following set of rules:

	-A conn_metrics -m connmark --mark 0x1/0x1
	-A INPUT -s 192.168.0.163 -p tcp -m multiport --dport 4712,4713 -j CONNMARK --or-mark 0x1
	-A INPUT -s 192.168.0.163 -p tcp -m multiport --dport 4712,4713 -j ACCEPT

With metrics, defined as:

	filter conn_metrics 1 media.packets
	filter INPUT 8 media.packets

Thus, allowing to count all the packets and bytes in the connection (by piping
them through "conn_metrics" chain before accepting by --state rule), while
retaining a stateful configuration for the firewall (i.e. making pass/filter
decisions on per-connection, not per-packet, basis).
See the comments in example config for more details on the metrics_conntrack
section.


##### Quick manual non-critical rule disabling

Rules can have --try option in them, in which case these rules will be disabled
if --skip-tries (-e) option is specified.

My use-case is not-so-important rules, depending on the DNS availability - some
single-ip hosts on the internet.
If link is currently down, iptables will fail to apply the whole ruleset, which
is much worse than just skipping these particular rules until the link will be
restored.

Naturally, option itself will never be passed to iptables.


##### Templating

WIth --jinja2 option, configuration file will be processed by jinja2, before
parsed as yaml.

See [jinja2 documentation](http://jinja.pocoo.org/docs/templates/) for template
syntax description.

Parameters passed to template.render():

* `hosts` - /etc/hosts as a mapping.

	For example, hosts-file line `1.2.3.4 sub.host.example.org` will produce following
	mapping (presented as yaml):

		sub.host.example.org: 1.2.3.4
		host.example.org:
			sub: 1.2.3.4
		org:
			example:
				host:
					sub: 1.2.3.4

* `cfg` - whatever is in --jinja2-config yaml, if passed, else None.

Extra filters/tags available:

* `dns` filter - will use `socket.getaddrinfo()` to resolve hostname into *unique* address.

	One optional argument is address family: "inet" or "inet6".

	If name resolves to non-unique address or doesn't resolve - exception will be
	raised (use --debug for more details, socket.gaierror's are remarkably
	non-informative), --try feature can be used to just skip rules that aren't
	critical in such cases, also see --replace-dns fallback option.

Templating requirement (or any other commandline option for that matter) can be
specified as emacs-local-var-style `# -*- jinja2: true -*-` headers (parsed as
yaml) at the first line(s) of the script.

Templating result as well as passed template context values can be dumped with
--jinja-dump flag.


### Requirements

Uses [PyYAML](http://pyyaml.org/wiki/PyYAML) module along with
[iptables](http://www.netfilter.org/) and [ipset](http://ipset.netfilter.org/)
binaries.

[Jinja2](http://jinja.pocoo.org/) is only required if --jinja2 opton is used.
