#!/usr/bin/env python
# -*- coding: utf-8 -*-


import itertools as it, operator as op, functools as ft
from subprocess import Popen, PIPE, STDOUT
from collections import defaultdict
import os, sys, yaml, re

import argparse
parser = argparse.ArgumentParser(
	description='Apply or check netfilter rules from/against configuration file.')
parser.add_argument('-n', '--no-revert', action='store_true',
	help='Do not schedule tables revert (in case of ssh lock),'
		' not recommended, since you never know when firewall may lock itself up.')
parser.add_argument('-x', '--no-ipsets', action='store_true',
	help='Do not process ipsets and related rules.')
parser.add_argument('-s', '--summary', action='store_true',
	help='Show diff between old and new tables afterwards.')
parser.add_argument('-d', '--dump', action='store_true',
	help='No changes, just dump resulting tables to stdout.')
parser.add_argument('-t', '--check-diff', action='store_true',
	help='No changes, return 0 ("identical") or 2 status (not 1, so it wont be'
		' confused with any generic error), depending on whether there are changes'
		' in configuration waiting to be applied (configuration differs from current'
		' iptables settings). Does not performs any ipset manipulations/comparisons.'
		' It is done in somewhat DANGEROUS way - tables get swapped for a short time.')
parser.add_argument('-c', '--conf',
	default=os.path.realpath(os.path.splitext(__file__)[0])+'.yaml',
	help='Path to configuration file (deafult: %(default)s).')
optz = parser.parse_args()

import logging as log
log.basicConfig(level=log.INFO)

os.umask(077)


builtins = set([ 'input', 'forward', 'output',
	'prerouting', 'mangle', 'postrouting' ])
extents = {
	'--mac-source': '-m mac',
	'--state': '-m state',
	'--src-range': '-m iprange',
	'--dst-range': '-m iprange',
	'--dport (\S+,)+\S+': '-m multiport',
	'--match-set': '-m set',
	'--pkt-type': '-m pkttype',
	'--uid-owner': '-m owner' }
extents = list( (re.compile('(?<=\s)((! )?'+k+')'), '%s \\1'%v)
	for k,v in extents.iteritems() )
pex = re.compile('(?<=-p\s)((\w+/)+\w+)'),\
	re.compile('(?<=port\s)((\d+/)+\d+)') # protocol extension
vmark = re.compile('(\s*-(v[46]))(?=\s|$)') # IP version mark

cfgs = open(optz.conf).read()
cfgs = cfgs.replace('\t', '  ') # I tend to use tabs, which are not YAML-friendly
cfgs = re.sub(re.compile(' *\\\\\n\s*', re.M), ' ', cfgs)
cfg = yaml.load(cfgs)


class Tables:
	v4, v6 = list(), list()
	v4_ext = v6_ext = None # comment flags (to skip repeating comments)
	v4_mark = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
	v6_mark = re.compile('[a-f0-9]{0,4}::([a-f0-9]{1,4}|/)') # far from perfect, but should do
	mark = None

	def append(self, rules, v=None):
		if not v:
			if self.mark: # rule was hand-marked with proto version
				v = self.mark
				self.mark = None
			else: # auto-determine if it's valid for each table
				if not self.v6_mark.search(rules): v = 'v4'
				if not self.v4_mark.search(rules):
					v = None if v else 'v6' # empty value means both tables
		for v in (('v4', 'v6') if not v else (v,)):
			table = getattr(self, v)
			if rules[0] == '#': setattr(self, '%s_ext'%v, rules)
			else:
				ext = getattr(self, '%s_ext'%v)
				if ext:
					table.append(ext)
					setattr(self, '%s_ext'%v, None)
				table.append(rules)

	def fetch(self, v=None):
		str = '\n'.join
		return (str(self.v4), str(self.v6)) if not v else str(getattr(self, v))

core = Tables()


def chainspec(chain):
	# Chain policy specification (like'input-lan/-', 'input/6' or 'input/+')
	if '/' in chain: chain,policy = chain.split('/', 1)
	else: policy = cfg['policy']
	if not policy or policy == '-': policy = 'DROP'
	elif policy.isdigit():
		if policy == '4': policy = ('ACCEPT', 'DROP')
		elif policy == '6': policy = ('DROP', 'ACCEPT')
		else: raise ValueError, 'Incorect policy specification'
	else: policy = 'ACCEPT'

	if '-' in chain: # like 'input-lan', for chain-global interface specification (useful in svc rules)
		if chain.startswith('input'): rule = '-i'
		elif chain.startswith('output'): rule = '-o'
		else: rule, pre = None, ()
		if rule:
			chain, pre = chain.split('-', 1)
			pre = (rule, pre)
	else: pre = ()

	return chain,policy,pre


def diff_summary(old, new):
	from tempfile import NamedTemporaryFile
	with NamedTemporaryFile(prefix='trilobite_old.') as bak_old,\
			NamedTemporaryFile(prefix='trilobite_new.') as bak_new:
		bak_old.write(old+'\n')
		bak_new.write(new+'\n')
		bak_old.flush(), bak_new.flush()
		Popen(cfg['fs']['bin']['diff'].split(' ') + [bak_old.name, bak_new.name]).wait()
	sys.stdout.write('\n\n')




### IPSETS
sets = defaultdict(list)
if not optz.no_ipsets and cfg.get('sets'):
	null = open('/dev/null', 'wb')

	# Generate new ipset specs
	for name,props in cfg['sets'].iteritems():
		if optz.check_diff:
			sets[name] = list() # has to exist, nothing more
			continue
		sets[name].append(['-N', name] + props['type'].split())
		for line in (props.get('contents') or list()): sets[name].append(['-A', name] + line.split())

	if not optz.check_diff:

		def pull_sets():
			ipset = Popen([cfg['fs']['bin']['ipset'], '--save'], stdout=PIPE)
			old_sets, stripped = '', list()
			for line in ipset.stdout:
				old_sets += line
				line = line.strip()
				if not line.startswith('#'): stripped.append(line) # strip comments
			if ipset.wait():
				log.fatal('ipsets backup failed, bailing out')
				sys.exit(1)
			return old_sets, '\n'.join(stripped)

		# Pull old sets' configuration
		old_sets, old_essence = pull_sets()

		# Clear namespace for used sets
		for name in list(sets):
			if not Popen([cfg['fs']['bin']['ipset'], '--list', name], stdout=null, stderr=STDOUT).wait():
				if Popen([cfg['fs']['bin']['ipset'], '--destroy', name], stdout=null, stderr=STDOUT).wait():
					log.warn('Failed to destroy ipset "{}", will be skipped on --restore'.format(name))
					sets[name] = list() # should not be restored
		# Push new sets
		ipset = Popen([cfg['fs']['bin']['ipset'], '--restore'], stdin=PIPE)
		ipset.stdin.write('\n'.join(it.imap(' '.join, it.chain.from_iterable(sets.viewvalues()))))
		ipset.stdin.write('\nCOMMIT\n')
		ipset.stdin.close()
		ipset.wait()

		# Pull new sets' configuration, to compare against old ones
		new_sets, new_essence = pull_sets()

		if old_essence != new_essence:
			# Backup old sets in backup.0 slot, rotating the rest of them
			i_slot = None
			for i in sorted(( cfg['fs']['bakz']['sets']%i
					for i in xrange(cfg['fs']['bakz']['keep']) ), reverse=True):
				if os.path.exists(i) and i_slot: os.rename(i, i_slot)
				i_slot = i
			else: open(i, 'w').write(old_sets)

			# Generate diff, if requested
			if optz.summary:
				log.info('IPSets:')
				diff_summary(old_essence, new_essence)

			# Schedule sets' revert if no commit action will be issued (to ensure that tables are in the sane state)
			if not optz.no_revert:
				at = Popen([cfg['fs']['bin']['at'], 'now', '+', str(cfg['fs']['bakz']['delay']), 'minutes'], stdin=PIPE)
				for name in sets:
					at.stdin.write('{} --destroy {}\n'.format(cfg['fs']['bin']['ipset'], name)) # destroy modified sets
				at.stdin.write('{} --restore < {}\n'.format(cfg['fs']['bin']['ipset'], i)) # restore from latest backup
				at.stdin.close()
				at.wait()




### IPTABLES
for table,chainz in cfg['tablez'].iteritems():
	if table != 'nat': add = core.append
	else: add = lambda x: core.append(x, 'v4')
	add('*'+table) # table header (like '*filter')

	try: svc = chainz.pop('svc')
	except KeyError: svc = {}

	# Form chainspec / initial rules, giving chains a 'clean', separated from chainspec, names
	for chain in chainz.keys():
		rulez = chainz[chain]
		del chainz[chain]
		chain, policy, pre = chainspec(chain)
		chainz[chain] = policy,\
			[(pre, [rulez] if isinstance(rulez, str) else rulez)] # only policy from the original chain is used

	# Extend chains w/ svc rules, if any
	if svc:
		cfgt = re.findall('\n(\s+)'+table+':(.+?)\n((\\1)\S+:.*|$)', cfgs, re.S)[0][1]
		ih = {}
		for name,rulez in svc.iteritems():
			indent = re.findall('^(\s+)'+name+':', cfgt, re.M)
			for i in indent:
				i = i.lstrip('\n')
				try:
					if name not in ih[i]: ih[i].append(name)
				except KeyError: ih[i] = [name]
		indent, ih = sorted(ih.iteritems(), key=lambda x: len(x[1]), reverse=True)[0]
		for name in re.findall('^'+indent+'(\S+):', cfgt, re.M):
			if name not in ih: continue
			try: pre = svc[name].iteritems() # full specification (dict w/ chain and rules list)
			except AttributeError: pre = [('input', svc[name])] # it's just a list of rules, defaults to input chain
			for chain,rulez in pre:
				chain, policy, pre = chainspec(chain) # policy here is silently ignored
				rulez = [rulez] if isinstance(rulez, str) else rulez
				chainz[chain][1].append((None, name))
				chainz[chain][1].append((pre, rulez))

	# Form actual tables
	chainz = sorted(chainz.iteritems(), key=lambda x: x[0].lower() in builtins)
	for name,chain in chainz:
		policy,ruleset = chain
		if name.lower() in builtins: name = name.upper()
		else: policy = '-'

		# Policy header (like ':INPUT ACCEPT [0:0]')
		policy_gen = lambda policy: '\n:%s %s '%(name, policy.upper()) + '[0:0]\n'
		try:
			v4,v6 = policy
			core.append(policy_gen(v4), 'v4')
			core.append(policy_gen(v6), 'v6')
		except (TypeError, ValueError): add(policy_gen(policy))

		header = None
		for base,rulez in ruleset:
			if rulez:
				for rule in rulez: # rule mangling

					# Rule base: comment / state extension
					if base == None: # it's a comment: store till first valid rule
						header = '# '+rulez
						break
					elif cfg['stateful'] and rule and '--state'\
							not in rule and  name == 'INPUT' and '--dport' in rule:
						pre = base + ('--state', 'NEW')
					else: pre = base

					try: # check rule for magical, inserted by hand, proto marks
						v, core.mark = vmark.findall(rule)[0]
					except (IndexError, TypeError): core.mark = None
					else: rule = rule.replace(v, '') # Strip magic

					# Special check for ipset module
					if rule and '--match-set' in rule:
						ipset = next(it.ifilter(None, rule.split('--match-set', 1)[-1].split()))
						if ipset not in sets:
							log.warn('Skipping rule for invalid/unknown ipset "{}"'.format(ipset))
							continue

					# Final rules (like '-A INPUT -j DROP')
					if not rule: rule = '-j', 'DROP'
					elif len(rule) == 1:
						if rule == 'x': rule = '-j', 'REJECT'
						elif rule == '<': rule = '-j', 'RETURN'
						else: rule = '-j', 'ACCEPT'
					# Rule actions
					elif rule.endswith(' x'): rule = rule[:-2], '-j', 'REJECT'
					elif rule.endswith(' -'): rule = rule[:-2], '-j', 'DROP'
					elif rule.endswith(' <'): rule = rule[:-2], '-j', 'RETURN'
					elif rule.endswith(' |'): rule = rule[:-2],
					elif '-j ' not in rule: rule = rule, '-j', 'ACCEPT'
					# Full rule, no action mangling is necessary
					else: rule = (rule,)

					rule = ' '.join(('-A', name) + pre + rule) # rule composition
					for k,v in extents: # rule extension (for example, adds '-m ...', where necessary)
						if v in rule: continue
						rule = k.sub(v, rule)

					# Protocol extension (clone rule for each proto)
					if rule:
						rules = [rule]
						for ex in pex:
							try:
								rules = list( ex.sub(_ex, rule) for rule in rules
									for _ex in ex.search(rule).groups()[0].split('/') )
							except AttributeError: pass # no matches
						rule = '\n'.join(rules)

					if header: # flush header, since section isn't empty
						add(header)
						header = None

					add(rule) # ta da!

	add('\nCOMMIT\n\n') # table end marker


# Ignore SIGHUP (in case of SSH break)
import signal
signal.signal(signal.SIGHUP, signal.SIG_IGN) # TODO: add instant-restore as a sighup handler?


def pull_table(v):
	iptables = Popen(cfg['fs']['bin'][v+'_pull'], stdout=PIPE)
	table, stripped = '', list()
	for line in iptables.stdout:
		table += line
		line = line.strip()
		if not (line.startswith('#') or line.startswith(':')):
			stripped.append(line) # strip comments and chains' packet counters
	if iptables.wait():
		log.fatal('iptables ({}) backup failed, bailing out'.format(v))
		sys.exit(1)
	return table, '\n'.join(stripped)

class TableUpdateError(Exception): pass

def push_table(v, table):
	iptables = Popen(cfg['fs']['bin'][v+'_push'], stdin=PIPE)
	iptables.stdin.write(table)
	iptables.stdin.close()
	if iptables.wait(): raise TableUpdateError('Failed to update table')


for v in ('v4', 'v6'):
	if not optz.dump:
		# Pull the old table, to check if it's similar to new one (no backup needed in that case)
		old_table, old_essence = pull_table(v)

		# Push new table
		try: push_table(v, core.fetch(v))
		except TableUpdateError as err: log.error(bytes(err))

		# Pull new table in iptables-save format, to compare against old one
		new_table, new_essence = pull_table(v)

		if old_essence != new_essence:
			if not optz.check_diff:
				# Backup old table in backup.0 slot, rotating the rest of them
				i_slot = None
				for i in sorted(( cfg['fs']['bakz'][v]%i
						for i in xrange(cfg['fs']['bakz']['keep']) ), reverse=True):
					if os.path.exists(i) and i_slot: os.rename(i, i_slot)
					i_slot = i
				else: open(i, 'w').write(old_table)
			else:
				push_table(v, old_table) # restore old table

			# Generate diff, if requested
			if optz.summary:
				log.info('%s table:'%v)
				diff_summary(old_essence, new_essence)

			# First diff means we're done if that's what is requested
			if optz.check_diff: sys.exit(2)

			# Schedule table revert if no commit action will be issued (to ensure that tables are in the sane state)
			if not optz.no_revert:
				at = Popen([cfg['fs']['bin']['at'], 'now', '+', str(cfg['fs']['bakz']['delay']), 'minutes'], stdin=PIPE)
				at.stdin.write('%s < %s\n'%(cfg['fs']['bin'][v+'_push'], i)) # restore from latest backup
				at.stdin.close()
				at.wait()

	else:
		log.info('%s table:'%v)
		sys.stdout.write(core.fetch(v)+'\n\n')
