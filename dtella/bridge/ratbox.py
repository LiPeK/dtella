"""
Dtella - RatboxIRCd Service Module
Copyright (C) 2008  Dtella Labs (http://www.dtella.org/)
Copyright (C) 2008  Paul Marks (http://www.pmarks.net/)
Copyright (C) 2008  Jacob Feisley  (http://www.feisley.com/)

$Id$

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
"""

from twisted.internet.protocol import ReconnectingClientFactory
from twisted.protocols.basic import LineOnlyReceiver
from twisted.internet import reactor, defer

import time
#import binascii
import array
import os
import struct 
import random
from hashlib import sha256
import re

import dtella.common.core as core
import dtella.local_config as local
from dtella.common.log import LOG
from dtella.common.util import CHECK
from dtella.common.util import Ad
from dtella.common.util import md5
import dtella.bridge_config as cfg
#from zope.interface import implements
#from zope.interface.verify import verifyClass
from dtella.bridge.bridge_server import ChannelUserModes
from dtella.bridge.bridge_server import IRCStateManager
from dtella.bridge.bridge_server import n_user
from dtella.bridge.bridge_server import irc_to_dc
from dtella.bridge.bridge_server import irc_strip
from dtella.bridge.bridge_server import getServiceConfig
from dtella.bridge.bridge_server import getBindIP

B_USER = "dtbridge"
B_REALNAME = "Dtella Bridge"

UUID_DIGITS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345679"

class RatboxConfig(object):
    chan_umodes = ChannelUserModes(
# conflicts with ratbox        ("q",  "owner",    "[~] owner$ $IRC\x01$$0$"),
        ("a",  "super-op", "[&] super-op$ $IRC\x01$$0$"),
        ("o",  "op",       "[@] op$ $IRC\x01$$0$"),
        ("h",  "half-op",  "[%] half-op$ $IRC\x01$$0$"),
        ("v",  "voice",    "[+] voice$ $IRC\x01$$0$"),
        (":P", "loser",    "[_]$ $IRC\x01$$0$"),
        (":V", "virtual",  "[>] virtual$ $IRC\x01$$0$"))

    use_rdns = True

    def __init__(self, host, port, ssl, sendpass, recvpass,
                 network_name, my_host, my_name, sid, channel,
                 hostmask_prefix, hostmask_keys):
        # Connection parameters for remote IRC server
        self.host = host                  # ip/hostname
        self.port = port                  # integer
        self.ssl = ssl                    # True/False
        self.sendpass = sendpass          # string
        self.recvpass = recvpass          # string (or None)
        self.network_name = network_name  # string

        # IRC Server Link parameters. The my_host parameter must match
        # the link block in your Ratbox ircd.conf file. 
        self.my_host = my_host
        self.my_name = my_name
        self.sid = sid                    # 3-char string (or None)

        # The channel Dtella will appear in.
        self.channel = channel

        # Host masking parameters.
        # TODO: figure out Ratbox hostmasking.
        self.hostmasker = HostMasker(hostmask_prefix, hostmask_keys)

    def startService(self, main):
        ifactory = IRCFactory(main)
        bind = (getBindIP(), 0)
        if self.ssl:
            from twisted.internet import ssl
            sslContext = ssl.ClientContextFactory()
            reactor.connectSSL(
                self.host, self.port, ifactory, sslContext, bindAddress=bind)
        else:
            reactor.connectTCP(self.host, self.port, ifactory, bindAddress=bind)


class IRCFactory(ReconnectingClientFactory):
    initialDelay = 10
    maxDelay = 60*20
    factor = 1.5

    def __init__(self, main):
        self.main = main

    def buildProtocol(self, addr):
        p = RatboxIRCServer(self.main)
        p.factory = self
        return p


class RatboxIRCServer(LineOnlyReceiver):
    showirc = False

    def __init__(self, main):
        self.setupSID()
        self.uuid_counter = 0

        self.ism = IRCStateManager(
            main=main, ircs=self, uuid_generator=self.generateUUID)
        self.server_name = None
        self.shutdown_deferred = None

        self.ping_dcall = None
        self.ping_waiting = False
        self.isFirstPing = True
        self.capabs = {}

        # The earliest observed channel creation time.
        self.chan_time = int(time.time())
        self.chan_init_mode = "+tn"

        # Generate a unique Q-line reason string, so we can detect if 
        # another bridge races and steals our prefix.
        self.qline_reason = (
            "Reserved for Dtella (%08X)" % random.randint(0, 0xFFFFFFFF))

    def setupSID(self):
        scfg = getServiceConfig()
        if scfg.sid:
            self.sid = scfg.sid
            return

        # Generate a 3-digit SID, based on some config constants.
        # This isn't the same algorithm as inspircd.cpp, but it doesn't
        # really matter.
        input_str = "%s\0%s" % (scfg.my_host, scfg.my_name)
        sid, = struct.unpack("!I", sha256(input_str).digest()[:4])
        self.sid = "%03d" % (sid % 999)

    def generateUUID(self):
        ctr = self.uuid_counter
        self.uuid_counter += 1

        uuid = ""
        for i in range(6):
            uuid = UUID_DIGITS[ctr % len(UUID_DIGITS)] + uuid
            ctr /= len(UUID_DIGITS)

        # There are over 2 billion UUIDs; just reconnect if we run out.
        if ctr > 0:
            self.transport.loseConnection()
            raise ValueError("Ran out of UUIDs")

        return self.sid + uuid

    def connectionMade(self):
        scfg = getServiceConfig()
        LOG.info("Connected to IRC server.")
        self.sendLine("PASS %s TS 6 :%s" % (scfg.sendpass, self.sid))
        self.sendLine("CAPAB :GLN TB ENCAP")
        self.sendLine(
            "SERVER %s 1 :%s" % (scfg.my_host, scfg.my_name))

    def sendLine(self, line):
        line = line.replace('\r', '').replace('\n', '')
        print "<: %s" % line
        if self.showirc:
            LOG.log(5, "<: %s" % line)
        LineOnlyReceiver.sendLine(self, line)

    def lineReceived(self, line):
        if not line:
            return

        print ">: %s" % line
        if self.showirc:
            LOG.log(5, ">: %s" % line)

        if line[0] == ':':
            try:
                prefix, line = line[1:].split(' ', 1)
            except ValueError:
                return
        else:
            prefix = ''

        try:
            line, trailing = line.split(' :', 1)
        except ValueError:
            args = line.split()
        else:
            args = line.split()
            args.append(trailing)

        try:
            f = getattr(self, 'handleCmd_%s' % args[0].upper())
        except AttributeError:
            pass
        else:
            f(prefix, args[1:])

    def handleCmd_PING(self, prefix, args):
        LOG.info("PING? PONG!")
        scfg = getServiceConfig()
        if len(args) == 1:
            self.sendLine("PONG %s :%s" % (scfg.my_host, args[0]))
        elif len(args) == 2:
            self.sendLine("PONG %s :%s" % (args[1], args[0]))
        if self.isFirstPing:
            self.isFirstPing = False
            self.handleCmd_EOS(self.server_name, [])

    def handleCmd_PONG(self, prefix, args):
        if self.ping_waiting:
            self.ping_waiting = False
            self.schedulePing()

    def handleCmd_NICK(self, prefix, args):
        # :268AAAAAF NICK Paul :1238303566
        old_uuid = prefix
        new_nick = args[0]
        try:
            u = self.ism.findUser(old_uuid)
        except KeyError:
            # This might be an echo from our KICK.
            LOG.warning("NICK: can't find source: %s" % old_uuid)
            return
        self.ism.changeNick(u, new_nick)

    def handleCmd_UID(self, prefix, args):
        # :sid UID nick hopcount nickTS +umodes user host
        #     ip uid :gecos
        nick = args[0]
        uuid = args[7]
        self.ism.addUser(nick, uuid)

    def handleCmd_JOIN(self, prefix, args):
        # :42XAAAAAD JOIN 1269812767 #dtella +
        uuid = prefix
        chans = args[1].split(',')

        scfg = getServiceConfig()
        if scfg.channel in chans:
            self.ism.joinChannel(self.ism.findUser(uuid))

    def handleCmd_SJOIN(self, prefix, args):
        # :268 SJOIN 1238298761 #opers +nt :@+268AAAAAF +268AAAAAE
        scfg = getServiceConfig()
        chan = args[1]
        if chan != scfg.channel:
            return

        # If we're not syncd yet, process the channel modes.
        if not self.ism.syncd:
            self.handleCmd_TMODE(prefix, args[:-1])

        # Keep track of earliest creation time for this channel.
        self.chan_time = min(self.chan_time, int(args[0]))
        # Keep track of initial channel mode (used in pushBotJoin)
        self.chan_init_mode = args[2]

        for uinfo in args[-1].split():
            modes = ""
            while uinfo[0] in "+@":
                if uinfo[0]=="+":
                    modes = modes + "v"
                elif uinfo[0]=="@":
                    modes = modes + "o"
                uinfo = uinfo[1:]
            uuid = uinfo

            u = self.ism.findUser(uuid)
            self.ism.joinChannel(u)

            changes = {}
            for m in modes:
                if m in scfg.chan_umodes.modes:
                    changes[m] = True

            if changes:
                self.ism.setChannelUserModes("", u, changes)

    def handleCmd_PART(self, prefix, args):
        uuid = prefix
        chans = args[0].split(',')

        scfg = getServiceConfig()
        if scfg.channel in chans:
            CHECK(self.ism.partChannel(self.ism.findUser(uuid)))

    def handleCmd_QUIT(self, prefix, args):
        uuid = prefix
        try:
            u = self.ism.findUser(uuid)
        except KeyError:
            LOG.warning("Can't quit user: %s" % uuid)
        else:
            self.ism.removeUser(u)

    def handleCmd_KICK(self, prefix, args):
        chan = args[0]
        l33t = prefix
        n00b = args[1]
        reason = irc_strip(args[2])

        scfg = getServiceConfig()
        if chan != scfg.channel:
            return

        # Rejoin the bot if it's killed.
        if self.ism.isMyBot(n00b):
            if self.ism.syncd:
                self.pushBotJoin()
            return

        l33t = self.ism.findUser(l33t).inick
        n = self.ism.findDtellaNode(inick=n00b)
        if n:
            self.ism.kickDtellaNode(n, l33t, reason)
        else:
            n00b_u = self.ism.findUser(n00b)
            message = (
                "%s has kicked %s: %s" %
                (irc_to_dc(l33t), irc_to_dc(n00b_u.inick), reason))
            CHECK(self.ism.partChannel(n00b_u, message))

    def handleCmd_KILL(self, prefix, args):
        # :darkhorse KILL }darkhorse :dhirc.com!darkhorse (TEST!!!)
        l33t = prefix
        n00b = args[0]
        reason = irc_strip(args[1])

        # In most cases, n00b is a UUID, but Anope seems to still use a nick.
        # Thus, we have to try both everywhere :-/

        # Reconnect the bot if it's killed.
        if self.ism.isMyBot(n00b):
            if self.ism.syncd:
                self.pushBotJoin(do_nick=True)
            return

        l33t = self.ism.findUser(l33t).inick

        # If n00b is a Dtella node, kick 'em.
        n = self.ism.findDtellaNode(inick=n00b)
        if n:
            self.ism.kickDtellaNode(
                n, l33t, "KILL: " + reason, send_quit=False)
            return

        # If n00b is an IRC user, treat it like a QUIT.
        try:
            n00b_u = self.ism.findUser(n00b)
        except KeyError:
            LOG.warning("Tried to KILL unknown user: %s" % n00b)
            return
        message = (
            "%s has KILL'd %s: %s" %
            (irc_to_dc(l33t), irc_to_dc(n00b_u.inick), reason))
        self.ism.removeUser(n00b_u, message)

    def handleCmd_TOPIC(self, prefix, args):
        # :268AAAAAO TOPIC #dtella :hello world
        whoset_uuid = prefix
        chan = args[0]
        text = irc_strip(args[-1])

        scfg = getServiceConfig()
        if chan == scfg.channel:
            whoset = self.ism.findUser(whoset_uuid).inick
            self.ism.setTopic(whoset, text)

    def handleCmd_TB(self, prefix, args):
        # :268 TB #dtella 1238306219 nick!host :hello
        chan = args[0]
        whoset = args[2].split('!', 1)[0]
        text = irc_strip(args[-1])

        scfg = getServiceConfig()
        if chan == scfg.channel:
            self.ism.setTopic(whoset, text)

    def handleCmd_TMODE(self, prefix, args):
        # :268AAAAAF TMODE 1238298761 #dtella +h-o 268AAAAAF 268AAAAAF
        whoset_uuid = prefix
        chan = args[1]
        change = args[2]
        margs = args[3:]

        scfg = getServiceConfig()
        if chan != scfg.channel:
            return

        try:
            whoset = self.ism.findUser(whoset_uuid).inick
        except KeyError:
            # Could be a server?
            whoset = ""

        on_off = True
        i = 0

        # User() -> {mode -> on_off}
        user_changes = {}

        # Dtella node modes that need unsetting.
        unset_modes = []
        unset_uuids = []

        for c in change:
            if c == '+':
                on_off = True
            elif c == '-':
                on_off = False
            elif c == 't':
                self.ism.setTopicLocked(whoset, on_off)
            elif c == 'm':
                self.ism.setModerated(whoset, on_off)
            elif c == 'k':
                # Skip over channel key
                i += 1
            elif c == 'l':
                # Skip over channel user limit
                i += 1
            elif c == 'b':
                banmask = margs[i]
                i += 1
                self.ism.setChannelBan(whoset, on_off, banmask)
            elif c in scfg.chan_umodes.modes:
                # Grab affected user
                uuid = margs[i]
                i += 1

                n = self.ism.findDtellaNode(inick=uuid)
                if n:
                    # If someone set a mode for a Dt node, unset it.
                    if on_off:
                        unset_modes.append(c)
                        unset_uuids.append(uuid)
                    continue

                # Get the IRC user we're modifying.
                try:
                    u = self.ism.findUser(uuid)
                except KeyError:
                    LOG.error("MODE: unknown user: %s" % uuid)
                    continue

                # Schedule a mode change for this user.
                user_changes.setdefault(u, {})[c] = on_off

        # Undo mode changes for Dtella nodes.
        if unset_modes:
            self.sendLine(
                ":%s TMODE %d %s -%s %s" %
                (self.ism.bot_user.uuid, self.chan_time, scfg.channel,
                 ''.join(unset_modes), ' '.join(unset_uuids)))

        # Send IRC user mode changes to Dtella
        for u, changes in user_changes.iteritems():
            self.ism.setChannelUserModes(whoset, u, changes)

    def handleCmd_BMASK(self, prefix, args):
        chan = args[1]
        bantype = args[2]
        bmasks = args[-1].split(' ')
        
        if bantype != 'b':
            return
        
        scfg = getServiceConfig()
        if chan != scfg.channel:
            return
        
        for banmask in bmasks:
            self.ism.setChannelBan("", True, banmask)

    """
    # handle net bans through ENCAP or DtellaBridge command interface
    def handleCmd_TKL(self, prefix, args):
        addrem = args[0]
        kind = args[1]

        if addrem == '+':
            on_off = True
        elif addrem == '-':
            on_off = False
        else:
            LOG.error("TKL: invalid modifier: '%s'" % addrem)
            return

        # :irc1.dhirc.com TKL + Z * 128.10.12.0/24 darkhorse!admin@dhirc.com 0 1171427130 :no reason
        if kind == 'Z' and args[2] == '*':
            cidr = args[3]
            self.ism.setNetworkBan(cidr, on_off)

        # :%s TKL + Q * %s* %s 0 %d :Reserved for Dtella
        elif kind == 'Q':
            nickmask = args[3]
            if on_off:
                reason = args[-1]
                self.ism.addQLine(nickmask, reason)
            else:
                self.ism.removeQLine(nickmask)
    """

    def handleCmd_SERVER(self, prefix, args):
        # SERVER hades.arpa 1 :ircd-ratbox test server
        if prefix:
            # Not my directly-connected server.
            return

        if self.server_name:
            # Could be a dupe?  Ignore it.
            return

        # We got a reply from the our connected IRC server, so our password
        # was just accepted.  Send the Dtella state information into IRC.

        # Save server name
        CHECK(args[0])
        self.server_name = args[0]

        LOG.info("IRC Server Name: %s" % self.server_name)

        # Tell the ReconnectingClientFactory that we're cool
        self.factory.resetDelay()

        # This isn't very correct, because the Dtella nicks
        # haven't been sent yet, but it's the best we can practically do.
        self.sendLine("SVINFO 6 6 0 :%d" %
                      (time.time(),))

    def handleCmd_EOS(self, prefix, args):
        if prefix != self.server_name:
            return
        if self.ism.syncd:
            return

        LOG.info("Finished receiving IRC sync data.")

        self.showirc = True

        # Check for conflicting bridges.
        if self.ism.findConflictingBridge():
            LOG.error("My nick prefix is in use! Terminating.")
            self.transport.loseConnection()
            reactor.stop()
            return

        # Set up nick reservation
        scfg = getServiceConfig()
        # FIX ME!
        #self.sendLine(
        #    ":%s ENCAP %s RESV 0 %s* 0 :Reserved for Dtella" %
        #    (scfg.my_host, self.server_name, cfg.dc_to_irc_prefix))
        self.ism.killConflictingUsers()

        self.addDefaultQLines()

        # Send my own bridge nick
        self.pushBotJoin(do_nick=True)

        # When we enter the syncd state, register this instance with Dtella.
        # This will eventually trigger event_DtellaUp, where we send our state.
        self.schedulePing()
        self.ism.addMeToMain()

    def handleCmd_WHOIS(self, prefix, args):
        # Somewhat simplistic handling of WHOIS requests
        if not (prefix and len(args) >= 1):
            return

        src = prefix
        who = args[-1]
        scfg = getServiceConfig()

        if who.lower() == self.ism.bot_user.inick.lower():
            self.pushWhoisReply(
                311, src, who, B_USER, scfg.my_host, '*', B_REALNAME)
            self.pushWhoisReply(
                312, src, who, scfg.my_host, scfg.my_name)
            self.pushWhoisReply(
                319, src, who, scfg.channel)
        else:
            n = self.ism.findDtellaNode(inick=who)
            if not (n and hasattr(n, 'hostmask')):
                return

            LOG.debug("WHOIS: n.hostmask = %s" % str(n.hostmask))
            LOG.debug("WHOIS: n.hostname = %s" % str(n.hostname))
            if n.hostmask is None:
                n.hostmask = str(n.hostname)

            self.pushWhoisReply(
                311, src, who, n_user(n.ipp), n.hostmask, '*',
                "Dtella %s" % n.dttag[3:])
            self.pushWhoisReply(
                312, src, who, scfg.my_host, scfg.my_name)
            self.pushWhoisReply(
                319, src, who, scfg.channel)

            if local.use_locations:
                self.pushWhoisReply(
                    320, src, who, "Location: %s"
                    % local.hostnameToLocation(n.hostname))

        self.pushWhoisReply(
            318, src, who, "End of /WHOIS list.")

    def pushWhoisReply(self, code, target, who, *strings):
        scfg = getServiceConfig()
        line = ":%s %d %s %s " % (scfg.my_host, code, target, who)
        LOG.debug("pushWhoisReply(): line = %s" % line)
        strings = list(strings)
        strings[-1] = ":" + strings[-1]
        LOG.debug("pushWhoisReply(): strings = %s" % str(strings))
        try:
            line += ' '.join(strings)
        except:
            LOG.error("pushWhoisReply(): 'strings' contains non string item!")
            return
        self.sendLine(line)

    def handleCmd_PRIVMSG(self, prefix, args):
        src_uuid = prefix
        target = args[0]
        text = args[1]
        flags = 0

        if (text[:8], text[-1:]) == ('\001ACTION ', '\001'):
            text = text[8:-1]
            flags |= core.SLASHME_BIT

        text = irc_strip(text)

        src_u = self.ism.findUser(src_uuid)
        src_nick = src_u.inick

        scfg = getServiceConfig()
        if target == scfg.channel:
            self.ism.sendChannelMessage(src_nick, text, flags)

        # :Global PRIVMSG $irc3.dhirc.com :TESTING....
        # Handle global messages delivered to the bridge.
        # FIXME: does this work with InspIRCd?
        elif target == "$" + scfg.my_host:
            flags |= core.NOTICE_BIT
            self.ism.sendChannelMessage(src_nick, text, flags)

        else:
            # ignore messages from users outside the main channel
            if not (src_u in self.ism.chanusers):
                return
            n = self.ism.findDtellaNode(inick=target)
            if n:
                self.ism.sendPrivateMessage(n, src_nick, text, flags)
            elif target == self.ism.bot_user.uuid:
                self.handleBridgeCommand(src_u, text)

    def handleCmd_NOTICE(self, prefix, args):
        src_uuid = prefix
        target = args[0]
        text = irc_strip(args[1])
        flags = core.NOTICE_BIT

        # ignore NOTICE AUTH on startup
        if not src_uuid:
            return

        src_u = self.ism.findUser(src_uuid)
        src_nick = src_u.inick

        scfg = getServiceConfig()
        if target == scfg.channel:
            self.ism.sendChannelMessage(src_nick, text, flags)
        else:
            # ignore messages from users outside the main channel
            if not (src_u in self.ism.chanusers):
                return
            n = self.ism.findDtellaNode(inick=target)
            if n:
                self.ism.sendPrivateMessage(n, src_nick, text, flags)

    def pushUID(self, uuid, nick, ident, host, cloak_host, modes, ip, gecos):
        # If an IP was provided, convert to a base64 parameter.
        if not ip:
            ip = '0'

        if not cloak_host:
            cloak_host = host

        scfg = getServiceConfig()
        now = time.time()
        self.sendLine(
            ":%s UID %s %d %d +%s %s %s %s %s :%s" %
            (self.sid, nick, 1, now, modes, ident, cloak_host,
             ip, uuid, gecos))

    def pushJoin(self, uuid, modes=""):
        scfg = getServiceConfig()
        self.sendLine(
            ":%s JOIN %d %s +" %
            (uuid, self.chan_time, scfg.channel))

    def pushQuit(self, uuid, reason=""):
        self.sendLine(":%s QUIT :%s" % (uuid, reason))

    def pushBotJoin(self, do_nick=False):
        scfg = getServiceConfig()
        uuid = self.ism.bot_user.uuid

        if do_nick:
            self.pushUID(
                uuid, self.ism.bot_user.inick,
                B_USER, scfg.my_host, None, "", None, B_REALNAME)

        # Join channel, and grant ops.
        scfg = getServiceConfig()
        self.sendLine(
            ":%s SJOIN %d %s %s :%s" %
            (self.sid, self.chan_time, scfg.channel, self.chan_init_mode, "@"+uuid))

    def pushRemoveQLine(self, nickmask):
        # FIXME
        scfg = getServiceConfig()
        LOG.info("Telling network to remove Q-line: %s" % nickmask)
        # self.sendLine("TKL - Q * %s %s" % (nickmask, scfg.my_host))

    def schedulePing(self):
        if self.ping_dcall:
            self.ping_dcall.reset(60.0)
            return

        def cb():
            self.ping_dcall = None

            if self.ping_waiting:
                LOG.error("Ping timeout!")
                self.transport.loseConnection()
            else:
                scfg = getServiceConfig()
                self.sendLine("PING :%s" % scfg.my_host)
                self.ping_waiting = True
                self.ping_dcall = reactor.callLater(60.0, cb)

        self.ping_dcall = reactor.callLater(60.0, cb)

    def event_AddDtNode(self, n, ident):
        self.pushUID(
            n.uuid, n.inick, ident, n.hostname, n.hostmask, "iwx",
            Ad().setRawIPPort(n.ipp).getTextIP(),
            "Dtella %s" % n.dttag[3:])
        self.pushJoin(n.uuid)

    def event_RemoveDtNode(self, n, reason):
        self.pushQuit(n.uuid, reason)

    def event_KillUser(self, u):
        scfg = getServiceConfig()
        LOG.info("Killing nick: " + u.inick)
        self.sendLine(":%s KILL %s :%s (nick reserved for Dtella)"
                      % (self.sid, u.uuid, scfg.my_host))

    def event_NodeSetTopic(self, n, topic):
        scfg = getServiceConfig()
        self.sendLine(
            ":%s TOPIC %s :%s" %
            (n.uuid, scfg.channel, topic))

    def event_Message(self, src_n, dst_u, text, action=False):
        scfg = getServiceConfig()
        if dst_u is None:
            target = scfg.channel
        else:
            target = dst_u.uuid

        if action:
            text = "\001ACTION %s\001" % text

        self.sendLine(":%s PRIVMSG %s :%s" % (src_n.uuid, target, text))

    def event_Notice(self, src_n, dst_u, text):
        scfg = getServiceConfig()
        if dst_u is None:
            target = scfg.channel
        else:
            target = dst_u.uuid

        self.sendLine(":%s NOTICE %s :%s" % (src_n.uuid, target, text))

    def shutdown(self):
        if self.shutdown_deferred:
            return self.shutdown_deferred

        # Remove nick ban
        self.pushRemoveQLine(cfg.dc_to_irc_prefix + "*")

        # Scream
        self.pushQuit(self.ism.bot_user.uuid, "AIEEEEEEE!")

        # Send SQUIT for completeness
        scfg = getServiceConfig()
        self.sendLine(":%s SQUIT %s :Bridge Shutting Down"
                      % (self.sid, scfg.my_host))

        # Close connection
        self.transport.loseConnection()

        # This will complete after loseConnection fires
        self.shutdown_deferred = defer.Deferred()
        return self.shutdown_deferred

    def connectionLost(self, result):
        LOG.info("Lost IRC connection.")
        if self.ism.syncd:
            self.ism.removeMeFromMain()

        if self.shutdown_deferred:
            self.shutdown_deferred.callback("Bye!")

        self.isFirstPing = True

    def addDefaultQLines(self):
        pass
        self.ism.qlines['NickWithoutDS'] = (re.compile("^\|(?!(\\[[Dd][Ss]((0[1-9])|(1[0-9])|(20)|([vV]))\\])[^ ]).*$"),"Niepoprawny nick! \n\nUzyj: [DSxx]Nick\ngdzie xx to 2 cyfry numeru akademika\nw przypadku DS Alfa: [DSV]Nick\ninfo: http://tnij.org/dtella-ms/regulamin\n")
        self.ism.qlines['BadCharsInNick'] = (re.compile(".*[!\"#%&'()*+,./:;=?@`~].*"), "Niepoprawny nick! \n\nNie uzywaj takich znakow: \n! \" # % & ' ( ) * + , . / : ; = ? @ ` ~\n")

    def handleBridgeCommand(self, src_u, command):
        if not 'o' in src_u.chanmodes:
            return
        
        def privToIrcUser(user, text):
            self.sendLine(":%s PRIVMSG %s :%s" % (self.ism.bot_user.uuid, src_u.uuid, text))
        
        privToIrcUser(src_u, "Sorry, not implemented yet :(")

class HostMasker(object):
    # UnrealIRCd-compatible hostmasking.
    # This is based on Unreal*/src/modules/cloak.c

    def __init__(self, prefix, keys):
        self.prefix = prefix
        self.keys = keys

    def maskHostname(self, host):
        # do not use hostmasking
        out = host
        return
        
        KEY1, KEY2, KEY3 = self.keys
        m = self.md5
        d = self.downsample

        alpha = d(m(m("%s:%s:%s" % (KEY1, host, KEY2)) + KEY3))
        out = "%s-%X" % (self.prefix, alpha)
    
        try:
            out += host[host.index('.'):]
        except ValueError:
            pass

        return out

    def maskIPv4(self, ip):
        # do not use hostmasking
        return ip
        
        KEY1, KEY2, KEY3 = self.keys
        m = self.md5
        d = self.downsample
        ipstr = self.ipstr

        ip = [int(o) for o in ip.split('.')]
        alpha = d(m(m("%s:%s:%s" % (KEY2, ipstr(ip[:4]), KEY3)) + KEY1))
        beta =  d(m(m("%s:%s:%s" % (KEY3, ipstr(ip[:3]), KEY1)) + KEY2))
        gamma = d(m(m("%s:%s:%s" % (KEY1, ipstr(ip[:2]), KEY2)) + KEY3))

        return "%X.%X.%X.IP" % (alpha, beta, gamma)

    def getChecksum(self):
        KEY1, KEY2, KEY3 = self.keys
        m = self.md5

        checksum = m("%s:%s:%s" % (KEY1, KEY2, KEY3))
        return "MD5:" + ''.join(("%02x" % ord(x))[::-1] for x in checksum)

    def md5(self, in_str):
        return md5(in_str).digest()

    def downsample(self, in_str):
        a = array.array('B', in_str)
        result = 0
        for i in range(0,16,4):
            result = (result << 8) + (a[i]^a[i+1]^a[i+2]^a[i+3])
        return result

    def ipstr(self, ip):
        return '.'.join(["%d" % o for o in ip])
