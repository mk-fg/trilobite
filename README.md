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

Any number of "-p proto1/proto2..." will be expanded as multiple rules, one for
each protocol, as tcp/udp in this case.

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

It builds a special file (location can be specified in config) with the "chain
rule_number name" syntax, example:

	INPUT 8 media.packets
	INPUT 12 sshd.connz
	INPUT 13 media.packets
	INPUT 13 pulse.connz

...which can be used later with netfilter counters (think "iptables -L INPUT
-vn") to produce stats for specific types of traffic on a local machine.
More complicated setups can probably use fwmarks (think "-j MARK").


### Requirements

Uses [PyYAML](http://pyyaml.org/wiki/PyYAML) module along with
[iptables](http://www.netfilter.org/) and [ipset](http://ipset.netfilter.org/)
binaries.
