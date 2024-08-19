#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim: set fileencoding=utf-8:noet

##  Copyright 2024 Bashclub https://github.com/bashclub
##  BSD-2-Clause
##
##  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
##
##  1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
##
##  2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
##
## THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
## THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
## BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
## GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
## LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## TrueNAS CheckMK Agent
## save the file in any Datastore in a subfolder named check_mk_agent and start it Task -> Init/Shutdown Scripts as POSTINIT
## optional create a folder local in the check_mk_agent folder and execute local checks (subdirs for caching data supported)

__VERSION__ = "0.64"

import sys
import os
import shlex
import glob
import re
import time
import json
import socket
import signal
import struct
import subprocess
import pwd
import threading
import ipaddress
import base64
import traceback
import syslog
import requests
import hashlib
from cryptography import x509
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from datetime import datetime
from xml.etree import cElementTree as ELementTree
from collections import Counter,defaultdict
from pprint import pprint
from socketserver import TCPServer,StreamRequestHandler
ISLINUX=sys.platform == "linux"
SCRIPTPATH = os.path.abspath(__file__)
if os.path.islink(SCRIPTPATH):
    SCRIPTPATH = os.path.realpath(os.readlink(SCRIPTPATH))
BASEDIR = os.path.dirname(SCRIPTPATH)
if BASEDIR.endswith("/bin"):
    BASEDIR = BASEDIR[:-4]
MK_CONFDIR = os.path.join(BASEDIR,"etc")
CHECKMK_CONFIG = os.path.join(MK_CONFDIR,"checkmk.conf")
LOCALDIR = os.path.join(BASEDIR,"local")
PLUGINSDIR = os.path.join(BASEDIR,"plugins")
SPOOLDIR = os.path.join(BASEDIR,"spool")

for _dir in (LOCALDIR, PLUGINSDIR, SPOOLDIR):
    if not os.path.exists(_dir):
        try:
            os.mkdir(_dir)
        except:
            pass

os.environ["MK_CONFDIR"] = MK_CONFDIR
os.environ["MK_LIBDIR"] = BASEDIR
os.environ["MK_VARDIR"] = BASEDIR

class object_dict(defaultdict):
    def __getattr__(self,name):
        return self[name] if name in self else ""

def etree_to_dict(t):
    d = {t.tag: {} if t.attrib else None}
    children = list(t)
    if children:
        dd = object_dict(list)
        for dc in map(etree_to_dict, children):
            for k, v in dc.items():
                dd[k].append(v)
        d = {t.tag: {k:v[0] if len(v) == 1 else v for k, v in dd.items()}}
    if t.attrib:
        d[t.tag].update(('@' + k, v) for k, v in t.attrib.items())
    if t.text:
        text = t.text.strip()
        if children or t.attrib:
            if text:
              d[t.tag]['#text'] = text
        else:
            d[t.tag] = text
    return d

def log(message,prio="notice"):
    priority = {
        "crit"      :syslog.LOG_CRIT,
        "err"       :syslog.LOG_ERR,
        "warning"   :syslog.LOG_WARNING,
        "notice"    :syslog.LOG_NOTICE, 
        "info"      :syslog.LOG_INFO, 
    }.get(str(prio).lower(),syslog.LOG_DEBUG)
    syslog.openlog(ident="checkmk_agent",logoption=syslog.LOG_PID | syslog.LOG_NDELAY,facility=syslog.LOG_DAEMON)
    syslog.syslog(priority,message)

def pad_pkcs7(message,size=16):
    _pad = size - (len(message) % size)
    if type(message) == str:
        return message + chr(_pad) * _pad
    else:
        return message + bytes([_pad]) * _pad

def check_pid(pid):
    try:
        os.kill(pid,0)
        return True
    except OSError: ## no permission check currently root
        return False

class checkmk_handler(StreamRequestHandler):
    def handle(self):
        with self.server._mutex:
            try:
                _strmsg = self.server.do_checks(remote_ip=self.client_address[0])
            except Exception as e:
                raise
                _strmsg = str(e).encode("utf-8")
            try:
                self.wfile.write(_strmsg)
            except:
                pass

class checkmk_checker(object):
    _available_sysctl_list = []
    _available_sysctl_temperature_list = []
    _check_cache = {}
    def encrypt_msg(self,message,password='secretpassword'):
        SALT_LENGTH = 8
        KEY_LENGTH = 32
        IV_LENGTH = 16
        PBKDF2_CYCLES = 10_000
        #SALT = b"Salted__"
        SALT = os.urandom(SALT_LENGTH)
        _backend = crypto_default_backend()
        _kdf_key =  PBKDF2HMAC(
            algorithm = hashes.SHA256(),
            length = KEY_LENGTH + IV_LENGTH,
            salt = SALT,
            iterations = PBKDF2_CYCLES,
            backend = _backend
        ).derive(password.encode("utf-8"))
        _key, _iv = _kdf_key[:KEY_LENGTH],_kdf_key[KEY_LENGTH:]
        _encryptor = Cipher(
            algorithms.AES(_key),
            modes.CBC(_iv),
            backend = _backend
        ).encryptor()
        message = message.encode("utf-8")
        message = pad_pkcs7(message)
        _encrypted_message = _encryptor.update(message) + _encryptor.finalize()
        return pad_pkcs7(b"03",10) + SALT + _encrypted_message

    def decrypt_msg(self,message,password='secretpassword'):
        SALT_LENGTH = 8
        KEY_LENGTH = 32
        IV_LENGTH = 16
        PBKDF2_CYCLES = 10_000
        message = message[10:] # strip header
        SALT = message[:SALT_LENGTH]
        message = message[SALT_LENGTH:]
        _backend = crypto_default_backend()
        _kdf_key =  PBKDF2HMAC(
            algorithm = hashes.SHA256(),
            length = KEY_LENGTH + IV_LENGTH,
            salt = SALT,
            iterations = PBKDF2_CYCLES,
            backend = _backend
        ).derive(password.encode("utf-8"))
        _key, _iv = _kdf_key[:KEY_LENGTH],_kdf_key[KEY_LENGTH:]
        _decryptor = Cipher(
            algorithms.AES(_key),
            modes.CBC(_iv),
            backend = _backend
        ).decryptor()
        _decrypted_message = _decryptor.update(message)
        try:
            return _decrypted_message.decode("utf-8").strip()
        except UnicodeDecodeError:
            return ("invalid key")

    def do_checks(self,debug=False,remote_ip=None,**kwargs):
        self._getosinfo()
        _errors = []
        _failed_sections = []
        _lines = ["<<<check_mk>>>"]
        _lines.append("AgentOS: {os}".format(**self._info))
        _lines.append("OSVersion: {os_version}".format(**self._info))
        _lines.append(f"Version: {__VERSION__}")
        _lines.append("Hostname: {hostname}".format(**self._info))
        if self.onlyfrom:
            _lines.append("OnlyFrom: {0}".format(",".join(self.onlyfrom)))

        _lines.append(f"LocalDirectory: {LOCALDIR}")
        _lines.append(f"PluginsDirectory: {PLUGINSDIR}")
        _lines.append(f"AgentDirectory: {MK_CONFDIR}")
        _lines.append(f"SpoolDirectory: {SPOOLDIR}")

        for _check in dir(self):
            if _check.startswith("check_"):
                _name = _check.split("_",1)[1]
                if _name in self.skipcheck:
                    continue
                try:
                    _lines += getattr(self,_check)()
                except:
                    _failed_sections.append(_name)
                    _errors.append(traceback.format_exc())

        if os.path.isdir(PLUGINSDIR):
            for _plugin_file in glob.glob(f"{PLUGINSDIR}/**",recursive=True):
                if os.path.isfile(_plugin_file) and os.access(_plugin_file,os.X_OK):
                    try:
                        _cachetime = int(_plugin_file.split(os.path.sep)[-2])
                    except:
                        _cachetime = 0
                    try:
                        if _cachetime > 0:
                            _lines.append(self._run_cache_prog(_plugin_file,_cachetime))
                        else:
                            _lines.append(self._run_prog(_plugin_file))
                    except:
                        _errors.append(traceback.format_exc())

        _lines.append("<<<local:sep(0)>>>")
        for _check in dir(self):
            if _check.startswith("checklocal_"):
                _name = _check.split("_",1)[1]
                if _name in self.skipcheck:
                    continue
                try:
                    _lines += getattr(self,_check)()
                except:
                    _failed_sections.append(_name)
                    _errors.append(traceback.format_exc())

        if os.path.isdir(LOCALDIR):
            for _local_file in glob.glob(f"{LOCALDIR}/**",recursive=True):
                if os.path.isfile(_local_file) and os.access(_local_file,os.X_OK):
                    try:
                        _cachetime = int(_local_file.split(os.path.sep)[-2])
                    except:
                        _cachetime = 0
                    try:
                        if _cachetime > 0:
                            _lines.append(self._run_cache_prog(_local_file,_cachetime))
                        else:
                            _lines.append(self._run_prog(_local_file))
                    except:
                        _errors.append(traceback.format_exc())

        if os.path.isdir(SPOOLDIR):
            _now = time.time()
            for _filename in glob.glob(f"{SPOOLDIR}/*"):
                _maxage = re.search("^(\d+)_",_filename)

                if _maxage:
                    _maxage = int(_maxage.group(1))
                    _mtime = os.stat(_filename).st_mtime
                    if _now - _mtime > _maxage:
                        continue
                with open(_filename) as _f:
                    _lines.append(_f.read())

        _lines.append("")
        if debug:
            sys.stdout.write("\n".join(_errors))
            sys.stdout.flush()
        if _failed_sections:
            _lines.append("<<<check_mk>>>")
            _lines.append("FailedPythonPlugins: {0}".format(",".join(_failed_sections)))

        if self.encrypt and not debug:
            return self.encrypt_msg("\n".join(_lines),password=self.encrypt)
        return "\n".join(_lines).encode("utf-8")

    def _getosinfo(self):
        _data = self._midclt("system.info")
        _truenas_version = re.findall(".?(SCALE)?-(\S+)",_data.get("version",""))[0]

        #_version_file = "/conf/base/etc/version"
        #_version_modified = os.stat(_version_file).st_mtime
        #_os,_version = open(_version_file,"rt").read().strip().split("-",1)
        self._info = {
            "os"                : "TrueNAS{0}".format(*_truenas_version),
            "os_version"        : "{1}".format(*_truenas_version),
            "version_age"       : int(time.time() - 0),
            "config_age"        : 0,
            "last_configchange" : "",
            "latest_version"    : "",
            "latest_date"       : "",
            "hostname"          : _data.get("hostname","")
        }

    def pidof(self,prog,default=None):
        _allprogs = re.findall("(\w+)\s+(\d+)",self._run_prog("ps ax -c -o command,pid"))
        return int(dict(_allprogs).get(prog,default))

    def _midclt(self,command,cachetime=0):
        if cachetime == 0:
            _res = self._run_prog(f"midclt call {command}")
        else:
            _res = self._run_cache_prog(f"midclt call {command}",cachetime=cachetime)
        try:
            return json.loads(_res)
        except:
            return {}

    def checklocal_firmware(self):
        if self._midclt("update.check_available",900).get("status","") == "UNAVAILABLE":
            return ["0 Firmware available=0 Version {0} up to date".format(self._info.get("os_version"))]
        else:
            _pending = self._midclt("update.pending",9000).get("new",{})
            return ["1 Firmware available=1 Version {0} ({1} available)".format(self._info.get("os_version"),_pending.get("version",""))]

    def check_label(self):
        _ret = ["<<<labels:sep(0)>>>"]
        if ISLINUX:
            if open("/proc/cpuinfo","rt").read().find("hypervisor") > -1:
                _ret.append('{"cmk/device_type":"vm"}')
        else:
            _dmsg = self._run_prog("dmesg",timeout=10)
            if _dmsg.lower().find("hypervisor:") > -1:
                _ret.append('{"cmk/device_type":"vm"}')
        return _ret

    def _check_bsd_net(self):
        _now = int(time.time())
        _ret = ["<<<statgrab_net>>>"]
        _interface_data = []
        _interface_data = self._run_prog("/usr/bin/netstat -i -b -d -n -W -f link").split("\n")
        _header = _interface_data[0].lower()
        _header = _header.replace("pkts","packets").replace("coll","collisions").replace("errs","error").replace("ibytes","rx").replace("obytes","tx")
        _header = _header.split()
        _interface_stats = dict(
            map(
                lambda x: (x.get("name"),x),
                [
                    dict(zip(_header,_ifdata.split()))
                    for _ifdata in _interface_data[1:] if _ifdata
                ]
            )
        )

        _ifconfig_out = self._run_prog("ifconfig -m -v -f inet:cidr,inet6:cidr")
        _ifconfig_out += "END" ## fix regex
        _all_interfaces = object_dict()
        for _interface, _data in re.findall("^(?P<iface>[\w.]+):\s(?P<data>.*?(?=^\w))",_ifconfig_out,re.DOTALL | re.MULTILINE):
            _interface_dict = object_dict()
            _interface_dict.update(_interface_stats.get(_interface,{}))
            _interface = _interface.replace(".","_")
            _interface_dict["up"] = "false"
            _interface_dict["systime"] = _now
            for _key, _val in re.findall("^\s*(\w+)[:\s=]+(.*?)$",_data,re.MULTILINE):
                if _key == "description":
                    _interface_dict["interface_name"] = _val.strip().replace("associated with jail: ","jail_").replace(" as nic: ","#").replace(" ","_").replace(":","_")
                if _key == "groups":
                    _interface_dict["groups"] = _val.strip().split()
                if _key == "ether":
                    _interface_dict["phys_address"] = _val.strip()
                if _key == "status" and _val.strip() == "active":
                    _interface_dict["up"] = "true"
                if _key == "flags":
                    _interface_dict["flags"] = _val
                if _key == "media":
                    _match = re.search("\((?P<speed>\d+G?)base(?:.*?<(?P<duplex>.*?)>)?",_val)
                    if _match:
                        _interface_dict["speed"] = _match.group("speed").replace("G","000")
                        _interface_dict["duplex"] = _match.group("duplex")
                if _key == "id":
                    _match = re.search("priority\s(\d+)",_val)
                    if _match:
                        _interface_dict["bridge_prio"] = _match.group(1)
                if _key == "member":
                    _member = _interface_dict.get("member",[])
                    _member.append(_val.split()[0])
                    _interface_dict["member"] = _member

            _all_interfaces[_interface] = _interface_dict
            if re.search("^[*]?(pflog|pfsync|lo)\d?",_interface):
                continue

            for _key,_val in _interface_dict.items():
                if _key in ("name","network","address","flags"):
                    continue
                if type(_val) in (str,int,float):
                    _ret.append(f"{_interface}.{_key} {_val}")

        _ret += ["<<<netctr>>>"]
        _out = self._run_prog("netstat -inb")
        for _line in re.finditer("^(?!Name|lo|plip)(?P<iface>\w+)\s+(?P<mtu>\d+).*?Link.*?\s+.*?\s+(?P<inpkts>\d+)\s+(?P<inerr>\d+)\s+(?P<indrop>\d+)\s+(?P<inbytes>\d+)\s+(?P<outpkts>\d+)\s+(?P<outerr>\d+)\s+(?P<outbytes>\d+)\s+(?P<coll>\d+)$",_out,re.M):
            _ret.append("{iface} {inbytes} {inpkts} {inerr} {indrop} 0 0 0 0 {outbytes} {outpkts} {outerr} 0 0 0 0 0".format(**_line.groupdict()))
        return _ret

    def check_net(self):
        if not ISLINUX:
            return self._check_bsd_net()
        _ret = ["<<<lnx_if>>>"]
        _ret.append("[start_iplink]")
        _ifaces = self._run_prog("ip address")
        _ret.append(_ifaces)
        _ret.append("[end_iplink]")
        _ret.append("<<<lnx_if:sep(58)>>>")
        for _iface in re.findall("\d+:\s(\w+)",_ifaces):
            _ret.append(f"[{_iface}]")
            try:
                _ethtool = self._run_prog(f"ethtool {_iface}")
                _ret += re.findall("(?:Speed|Duplex|Link detected|Auto-negotiation).*",_ethtool)
                _mac = open(f"/sys/class/net/{_iface}/address","rt").read().strip()
            except:
                pass
            _ret.append(f"Address: {_mac}")

        if os.path.isdir("/proc/net/bonding"):
            _ret.append("<<<lnx_bonding:sep(58)>>>")
            for _bond in os.listdir("/proc/net/bonding"):
                _ret.append(f"==> ./{_bond} <==")
                _ret.append(open(f"/proc/net/bonding/{_bond}","rt").read())
        return _ret

    def checklocal_samba(self):
        if not os.path.exists("/bin/smbstatus") and not not os.path.exists("/usr/local/bin/smbstatus") :
            return []
        try:
            _json = self._run_prog("smbstatus --json")
            _data = json.loads(_json)
            _locks = _data.get("locked_files",[])
            _xlocks = len(list(filter(lambda x: True in x.get("oplock",{}).values(),_locks)))
            _shared_locks = len(list(filter(lambda x: True not in x.get("oplock",{}).values(),_locks)))
            _sessions = len(_data.get("sessions",[]))
            return [f"0 Samba share_locks={_shared_locks}|exclusive_locks={_xlocks}|active_sessions={_sessions} {_sessions} User active"]
        except:
            return ["2 Samba share_locks=0|exclusive_locks=0|active_sessions=0 Server Error"]

    def check_ntp(self):
        if not os.path.exists("/usr/bin/ntpq"):
            return []
        _ret = ["<<<ntp>>>"]
        for _line in self._run_prog("ntpq -np",timeout=30).split("\n")[2:]:
            if _line.strip():
                _ret.append("{0} {1}".format(_line[0],_line[1:]))
        return _ret

    def check_smartinfo(self):
        if not os.path.exists("/sbin/smartctl") and not os.path.exists("/usr/local/sbin/smartctl"):
            return []
        REGEX_DISCPATH = re.compile("(sd[a-z]+|da[0-9]+|nvme[0-9]+|ada[0-9]+)$")
        _disk_descriptions = {}
        for _disk in self._midclt("disk.query"):
            _diskname = re.sub("(nvme\d+)n\d","\\1",_disk.get("name"))
            _disk_descriptions[_diskname] = _disk.get("description","")
        _ret = ["<<<disk_smart_info:sep(124)>>>"]
        for _dev in filter(lambda x: REGEX_DISCPATH.match(x),os.listdir("/dev/")):
            try:
                _ret.append(str(smart_disc(_dev,description=_disk_descriptions.get(f"{_dev}"))))
            except:
                pass
        return _ret

    def check_ipmi(self):
        if not os.path.exists("/bin/ipmitool") and not os.path.exists("/usr/local/bin/ipmitool"):
            return []
        _out = self._run_prog("ipmitool sensor list")
        _ipmisensor = re.findall("^(?!.*\sna\s.*$).*",_out,re.M)
        if _ipmisensor:
            return ["<<<ipmi:sep(124)>>>"] + _ipmisensor
        return []

    def check_temperature(self):
        if ISLINUX:
            return []
        _ret = ["<<<lnx_thermal:sep(124)>>>"]
        _out = self._run_prog("sysctl dev.cpu",timeout=10)
        _cpus = dict([_v.split(": ") for _v in _out.split("\n") if len(_v.split(": ")) == 2])
        _cpu_temperatures = list(map(
            lambda x: float(x[1].replace("C","")),
            filter(
                lambda x: x[0].endswith("temperature"),
                _cpus.items()
            )
        ))
        if _cpu_temperatures:
            _cpu_temperature = int(max(_cpu_temperatures) * 1000)
            _ret.append(f"CPU|enabled|unknown|{_cpu_temperature}")
        
        _count = 0
        for _tempsensor in self._available_sysctl_temperature_list:
            _out = self._run_prog(f"sysctl -n {_tempsensor}",timeout=10)
            if _out:
                try:
                    _zone_temp = int(float(_out.replace("C","")) * 1000)
                except ValueError:
                    _zone_temp = None
                if _zone_temp:
                    if _tempsensor.find(".pchtherm.") > -1:
                        _ret.append(f"thermal_zone{_count}|enabled|unknown|{_zone_temp}|111000|critical|108000|passive")
                    else:
                        _ret.append(f"thermal_zone{_count}|enabled|unknown|{_zone_temp}")
                    _count += 1
        if len(_ret) < 2:
           return []
        return _ret


    def check_df(self):
        _ret = ["<<<df>>>"]
        _ret += self._run_prog("df -kTP -t ufs").split("\n")[1:]
        return _ret

    def check_diskstat(self):
        if not ISLINUX:
            return []
        _ret = ["<<<diskstat>>>"]
        _now = int(time.time())
        _ret.append(f"{_now}")
        for _disk in list(filter(lambda x: re.search("nvme[0-9]+n[0-9]+|[svh]d[a-z]*[0-9]*|zd[0-9]+",x),open("/proc/diskstats","rt").readlines())):
            _ret.append(_disk.strip())
        return _ret

    def check_ssh(self):
        _ret = ["<<<sshd_config>>>"]
        with open("/etc/ssh/sshd_config","r") as _f:
            for _line in _f.readlines():
                if re.search("^[a-zA-Z]",_line):
                    _ret.append(_line.replace("\n",""))
        return _ret

    def _check_bsd_kernel(self):
        _ret = ["<<<kernel>>>"]
        _out = self._run_prog("sysctl vm.stats",timeout=10)
        _kernel = dict([_v.split(": ") for _v in _out.split("\n") if len(_v.split(": ")) == 2])
        _ret.append("{0:.0f}".format(time.time()))
        _ret.append("cpu {0} {1} {2} {4} {3}".format(*(self._run_prog("sysctl -n kern.cp_time","").split(" "))))
        _ret.append("ctxt {0}".format(_kernel.get("vm.stats.sys.v_swtch")))
        _sum = sum(map(lambda x: int(x[1]),(filter(lambda x: x[0] in ("vm.stats.vm.v_forks","vm.stats.vm.v_vforks","vm.stats.vm.v_rforks","vm.stats.vm.v_kthreads"),_kernel.items()))))
        _ret.append("processes {0}".format(_sum))
        return _ret

    def check_kernel(self):
        if not ISLINUX:
            return self._check_bsd_kernel()
        _ret = ["<<<kernel>>>"]
        _now = int(time.time())
        _ret.append(f"{_now}")
        _ret.append(open("/proc/vmstat","rt").read())
        _ret.append(open("/proc/stat","rt").read())
        return _ret

    def _check_bsd_mem(self):
        _ret = ["<<<statgrab_mem>>>"]
        _pagesize = int(self._run_prog("sysctl -n hw.pagesize"))
        _out = self._run_prog("sysctl vm.stats",timeout=10)
        _mem = dict(map(lambda x: (x[0],int(x[1])) ,[_v.split(": ") for _v in _out.split("\n") if len(_v.split(": ")) == 2]))
        _mem_cache = _mem.get("vm.stats.vm.v_cache_count") * _pagesize
        _mem_free = _mem.get("vm.stats.vm.v_free_count") * _pagesize
        _mem_inactive = _mem.get("vm.stats.vm.v_inactive_count") * _pagesize
        _mem_total = _mem.get("vm.stats.vm.v_page_count") * _pagesize
        _mem_avail = _mem_inactive + _mem_cache + _mem_free
        _mem_used = _mem_total - _mem_avail # fixme mem.hw
        _ret.append("mem.cache {0}".format(_mem_cache))
        _ret.append("mem.free {0}".format(_mem_free))
        _ret.append("mem.total {0}".format(_mem_total))
        _ret.append("mem.used {0}".format(_mem_used))
        _ret.append("swap.free 0")
        _ret.append("swap.total 0")
        _ret.append("swap.used 0")
        return _ret

    def check_mem(self):
        if not ISLINUX:
            return self._check_bsd_mem()
        _ret = ["<<<mem>>>"]
        _ret.append(open("/proc/meminfo","rt").read())
        return _ret

    def check_zpool(self):
        _ret = ["<<<zpool_status>>>"]
        _ret.append(self._run_prog("zpool status -x"))
        _ret.append("<<<zpool>>>")
        _ret.append(self._run_prog("zpool list"))
        return _ret

    def check_zfs(self):
        _ret = ["<<<zfsget:sep(9)>>>"]
        _ret.append(self._run_prog("zfs get -t filesystem,volume -Hp name,quota,used,avail,mountpoint,type"))
        _ret.append("[df]")
        _ret.append(self._run_prog("df -kP -t zfs"))
        _ret.append("<<<zfs_arc_cache>>>")
        if ISLINUX:
            _arc = "".join(open("/proc/spl/kstat/zfs/arcstats","rt").readlines()[2:])
            for _stat in re.findall("^([\w_]+)\s*\d\s*(\d+)",_arc,re.M):
                _ret.append("{0} = {1}".format(*_stat))
        else:
            _ret.append(self._run_prog("sysctl -q kstat.zfs.misc.arcstats").replace("kstat.zfs.misc.arcstats.","").replace(": "," = ").strip())

        return _ret

    def _check_bsd_cpu(self):
        _ret = ["<<<cpu>>>"]
        _loadavg = self._run_prog("sysctl -n vm.loadavg").strip("{} \n")
        _proc = self._run_prog("top -b -n 1").split("\n")[1].split(" ")
        _proc = "{0}/{1}".format(_proc[3],_proc[0])
        _lastpid = self._run_prog("sysctl -n kern.lastpid").strip(" \n")
        _ncpu = self._run_prog("sysctl -n hw.ncpu").strip(" \n")
        _ret.append(f"{_loadavg} {_proc} {_lastpid} {_ncpu}")
        return _ret

    def check_cpu(self):
        if not ISLINUX:
            return self._check_bsd_cpu()
        _ret = ["<<<cpu>>>"]
        _ret += open("/proc/loadavg","rt").readlines()
        if os.path.exists("/proc/sys/kernel/threads-max"):
            _ret += open("/proc/sys/kernel/threads-max","rt").readlines()
        return _ret

    def check_tcp(self):
        _ret = ["<<<tcp_conn_stats>>>"]
        _out = self._run_prog("netstat -na")
        counts = Counter(re.findall("ESTABLISHED|LISTEN",_out))
        for _key,_val in counts.items():
            _ret.append(f"{_key} {_val}")
        return _ret

    def check_ps(self):
        _ret = ["<<<ps>>>"]
        _out = self._run_prog("ps ax -o state,user,vsz,rss,pcpu,command")
        for _line in re.finditer("^(?P<stat>\w+)\s+(?P<user>\w+)\s+(?P<vsz>\d+)\s+(?P<rss>\d+)\s+(?P<cpu>[\d.]+)\s+(?P<command>.*)$",_out,re.M):
            _ret.append("({user},{vsz},{rss},{cpu}) {command}".format(**_line.groupdict()))
        return _ret

    def _check_bsd_uptime(self):
        _ret = ["<<<uptime>>>"]
        _uptime_sec = time.time() - int(self._run_prog("sysctl -n kern.boottime").split(" ")[3].strip(" ,"))
        _idle_sec = re.findall("(\d+):[\d.]+\s+\[idle\]",self._run_prog("ps axw"))[0]
        _ret.append(f"{_uptime_sec} {_idle_sec}")
        return _ret

    def check_uptime(self):
        if not ISLINUX:
            return self._check_bsd_uptime()
        _ret = ["<<<uptime>>>"]
        _ret += open("/proc/uptime","rt").readlines()
        return _ret

    def _run_prog(self,cmdline="",*args,shell=False,timeout=60,ignore_error=False):
        if type(cmdline) == str:
            _process = shlex.split(cmdline,posix=True)
        else:
            _process = cmdline
        try:
            return subprocess.check_output(_process,encoding="utf-8",shell=shell,stderr=subprocess.DEVNULL,timeout=timeout)
        except subprocess.CalledProcessError as e:
            if ignore_error:
                return e.stdout
            return ""
        except subprocess.TimeoutExpired:
            return ""

    def _run_cache_prog(self,cmdline="",cachetime=10,*args,shell=False,ignore_error=False):
        if type(cmdline) == str:
            _process = shlex.split(cmdline,posix=True)
        else:
            _process = cmdline
        _process_id = "".join(_process)
        _runner = self._check_cache.get(_process_id)
        if _runner == None:
            _runner = checkmk_cached_process(_process,shell=shell,ignore_error=ignore_error)
            self._check_cache[_process_id] = _runner
        return _runner.get(cachetime)

class checkmk_cached_process(object):
    def __init__(self,process,shell=False,ignore_error=False):
        self._processs = process
        self._islocal = os.path.dirname(process[0]).startswith(LOCALDIR)
        self._shell = shell
        self._ignore_error = ignore_error
        self._mutex = threading.Lock()
        with self._mutex:
            self._data = (0,"")
            self._thread = None

    def _runner(self,timeout):
        try:
            _data = subprocess.check_output(self._processs,shell=self._shell,encoding="utf-8",stderr=subprocess.DEVNULL,timeout=timeout)
        except subprocess.CalledProcessError as e:
            if self._ignore_error:
                _data = e.stdout
            else:
                _data = ""
        except subprocess.TimeoutExpired:
            _data = ""
        with self._mutex:
            self._data = (int(time.time()),_data)
            self._thread = None

    def get(self,cachetime):
        with self._mutex:
            _now = time.time()
            _mtime = self._data[0]
        if _now - _mtime > cachetime or cachetime == 0:
            if not self._thread:
                if cachetime > 0:
                    _timeout = cachetime*2-1
                else:
                    _timeout = None
                with self._mutex:
                    self._thread = threading.Thread(target=self._runner,args=[_timeout])
                self._thread.start()

            self._thread.join(30) ## waitmax
        with self._mutex:
            _mtime, _data = self._data
        if not _data.strip():
            return ""
        if self._islocal:
            _data = "".join([f"cached({_mtime},{cachetime}) {_line}" for _line in _data.splitlines(True) if len(_line.strip()) > 0])
        else:
            _data = re.sub("\B[<]{3}(.*?)[>]{3}\B",f"<<<\\1:cached({_mtime},{cachetime})>>>",_data)
        return _data

class checkmk_server(TCPServer,checkmk_checker):
    def __init__(self,port,pidfile,onlyfrom=None,encrypt=None,skipcheck=None,**kwargs):
        self.pidfile = pidfile
        self.onlyfrom = onlyfrom.split(",") if onlyfrom else None
        self.skipcheck = skipcheck.split(",") if skipcheck else []
        self.encrypt = encrypt
        self._mutex = threading.Lock()
        self.user = pwd.getpwnam("root")
        self.allow_reuse_address = True
        TCPServer.__init__(self,("",port),checkmk_handler,bind_and_activate=False)

    def _change_user(self):
        _, _, _uid, _gid, _, _, _ = self.user
        if os.getuid() != _uid:
            os.setgid(_gid)
            os.setuid(_uid)

    def verify_request(self, request, client_address):
        if self.onlyfrom and client_address[0] not in self.onlyfrom:
            log("Client {0} not allowed".format(*client_address),"warn")
            return False
        return True

    def server_start(self):
        log("starting checkmk_agent")
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGHUP, self._signal_handler)
        self._change_user()
        try:
            self.server_bind()
            self.server_activate()
        except:
            self.server_close()
            raise
        try:
            self.serve_forever()
        except KeyboardInterrupt:
            sys.stdout.flush()
            sys.stdout.write("\n")
            pass

    def cmkclient(self,checkoutput="127.0.0.1",port=None,encrypt=None,**kwargs):
        _sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        _sock.settimeout(3)
        try:
            _sock.connect((checkoutput,port))
            _sock.settimeout(None)
            _msg = b""
            while True:
                _data = _sock.recv(2048)
                if not _data:
                    break
                _msg += _data
        except TimeoutError:
            sys.stderr.write("timeout\n")
            sys.stderr.flush()
            sys.exit(1)

        if _msg[:2] == b"03":
            if encrypt:
                return self.decrypt_msg(_msg,encrypt)
            else:
                pprint(repr(_msg[:2]))
                return "missing key"
        return _msg.decode("utf-8")

    def _signal_handler(self,signum,*args):
        if signum in (signal.SIGTERM,signal.SIGINT):
            log("stopping checkmk_agent")
            threading.Thread(target=self.shutdown,name='shutdown').start()
            sys.exit(0)

    def daemonize(self):
        try:
            pid = os.fork()
            if pid > 0:
                ## first parent
                sys.exit(0)
        except OSError as e:
            sys.stderr.write("Fork failed\n")
            sys.stderr.flush()
            sys.exit(1)
        os.chdir("/")
        os.setsid()
        os.umask(0)
        try:
            pid = os.fork()
            if pid > 0:
                ## second
                sys.exit(0)
        except OSError as e:
            sys.stderr.write("Fork 2 failed\n")
            sys.stderr.flush()
            sys.exit(1)
        sys.stdout.flush()
        sys.stderr.flush()
        self._redirect_stream(sys.stdin,None)
        self._redirect_stream(sys.stdout,None)
        self._redirect_stream(sys.stderr,None)
        with open(self.pidfile,"wt") as _pidfile:
            _pidfile.write(str(os.getpid()))
        os.chown(self.pidfile,self.user[2],self.user[3])
        try:
            self.server_start()
        finally:
            try:
                os.remove(self.pidfile)
            except:
                pass
        
    @staticmethod
    def _redirect_stream(system_stream,target_stream):
        if target_stream is None:
            target_fd = os.open(os.devnull, os.O_RDWR)
        else:
            target_fd = target_stream.fileno()
        os.dup2(target_fd, system_stream.fileno())

    def __del__(self):
        pass ## todo


REGEX_SMART_VENDOR = re.compile(r"^\s*(?P<num>\d+)\s(?P<name>[-\w]+).*\s{2,}(?P<value>[\w\/() ]+)$",re.M)
REGEX_SMART_DICT = re.compile(r"^(.*?):\s*(.*?)$",re.M)
class smart_disc(object):
    def __init__(self,device,description=""):
        self.device = device
        if description:
            self.description = description
        MAPPING = {
            "Model Family"      : ("model_family"       ,lambda x: x),
            "Model Number"      : ("model_family"       ,lambda x: x),
            "Product"           : ("model_family"       ,lambda x: x),
            "Vendor"            : ("vendor"             ,lambda x: x),
            "Revision"          : ("revision"           ,lambda x: x),
            "Device Model"      : ("model_type"         ,lambda x: x),
            "Serial Number"     : ("serial_number"      ,lambda x: x),
            "Serial number"     : ("serial_number"      ,lambda x: x),
            "Firmware Version"  : ("firmware_version"   ,lambda x: x),
            "User Capacity"     : ("capacity"           ,lambda x: x.split(" ")[0].replace(",","")),
            "Total NVM Capacity": ("capacity"           ,lambda x: x.split(" ")[0].replace(",","")),
            "Rotation Rate"     : ("rpm"                ,lambda x: x.replace(" rpm","")),
            "Form Factor"       : ("formfactor"         ,lambda x: x),
            "SATA Version is"   : ("transport"          ,lambda x: x.split(",")[0]),
            "Transport protocol": ("transport"          ,lambda x: x),
            "SMART support is"  : ("smart"              ,lambda x: int(x.lower() == "enabled")),
            "Critical Warning"  : ("critical"           ,lambda x: self._saveint(x,base=16)),
            "Temperature"       : ("temperature"        ,lambda x: x.split(" ")[0]),
            "Data Units Read"   : ("data_read_bytes"    ,lambda x: x.split(" ")[0].replace(",","")),
            "Data Units Written": ("data_write_bytes"   ,lambda x: x.split(" ")[0].replace(",","")),
            "Power On Hours"    : ("poweronhours"       ,lambda x: x.replace(",","")),
            "number of hours powered up" :  ("poweronhours" ,lambda x: x.replace(",","")),
            "Power Cycles"      : ("powercycles"        ,lambda x: x.replace(",","")),
            "NVMe Version"      : ("transport"          ,lambda x: f"NVMe {x}"),
            "Raw_Read_Error_Rate"   : ("error_rate"     ,lambda x: x.split(" ")[-1].replace(",","")),
            "Reallocated_Sector_Ct" : ("reallocate"     ,lambda x: x.replace(",","")),
            "Seek_Error_Rate"       : ("seek_error_rate",lambda x: x.split(" ")[-1].replace(",","")),
            "Power_Cycle_Count"     : ("powercycles"        ,lambda x: x.replace(",","")),
            "Temperature_Celsius"   : ("temperature"        ,lambda x: x.split(" ")[0]),
            "Temperature_Internal"  : ("temperature"        ,lambda x: x.split(" ")[0]),
            "Drive_Temperature"     : ("temperature"        ,lambda x: x.split(" ")[0]),
            "UDMA_CRC_Error_Count"  : ("udma_error"         ,lambda x: x.replace(",","")),
            "Offline_Uncorrectable" : ("uncorrectable"      ,lambda x: x.replace(",","")),
            "Power_On_Hours"        : ("poweronhours"       ,lambda x: x.replace(",","")),
            "Spin_Retry_Count"      : ("spinretry"          ,lambda x: x.replace(",","")),
            "Current_Pending_Sector": ("pendingsector"      ,lambda x: x.replace(",","")),
            "Current Drive Temperature"         : ("temperature"        ,lambda x: x.split(" ")[0]),
            "Reallocated_Event_Count"           : ("reallocate_ev"      ,lambda x: x.split(" ")[0]),
            "Warning  Comp. Temp. Threshold"    : ("temperature_warn"   ,lambda x: x.split(" ")[0]),
            "Critical Comp. Temp. Threshold"    : ("temperature_crit"   ,lambda x: x.split(" ")[0]),
            "Media and Data Integrity Errors"   : ("media_errors"       ,lambda x: x),
            "Airflow_Temperature_Cel"           : ("temperature"        ,lambda x: x),
            "number of hours powered up"        : ("poweronhours"       ,lambda x: x.split(".")[0]),
            "Accumulated start-stop cycles"     : ("powercycles"        ,lambda x: x),
            "Available Spare"                   : ("wearoutspare"       ,lambda x: x.replace("%","")),
            "SMART overall-health self-assessment test result" : ("smart_status" ,lambda x: int(x.lower().strip() == "passed")),
            "SMART Health Status"   : ("smart_status" ,lambda x: int(x.lower() == "ok")),
        }
        self._get_data()
        for _key, _value in REGEX_SMART_DICT.findall(self._smartctl_output):
            if _key in MAPPING.keys():
                _map = MAPPING[_key]
                setattr(self,_map[0],_map[1](_value))

        for _vendor_num,_vendor_text,_value in REGEX_SMART_VENDOR.findall(self._smartctl_output):
            if _vendor_text in MAPPING.keys():
                _map = MAPPING[_vendor_text]
                setattr(self,_map[0],_map[1](_value))

    def _saveint(self,val,base=10):
        try:
            return int(val,base)
        except (TypeError,ValueError):
            return 0

    def _get_data(self):
        try:
            self._smartctl_output = subprocess.check_output(["smartctl","-a","-n","standby", f"/dev/{self.device}"],encoding=sys.stdout.encoding,timeout=10)
        except subprocess.CalledProcessError as e:
            if e.returncode & 0x1:
                raise
            _status = ""
            self._smartctl_output = e.output
            if e.returncode & 0x2:
                _status = "SMART Health Status:  CRC Error"
            if e.returncode & 0x4:
                _status = "SMART Health Status:  PREFAIL"
            if e.returncode & 0x3:
                _status = "SMART Health Status:  DISK FAILING"
                
            self._smartctl_output += f"\n{_status}\n"
        except subprocess.TimeoutExpired:
            self._smartctl_output += "\nSMART smartctl Timeout\n"

    def __str__(self):
        _ret = []
        if getattr(self,"transport","").lower() == "iscsi": ## ignore ISCSI
            return ""
        if not getattr(self,"model_type",None):
            self.model_type = getattr(self,"model_family","unknown")
        for _k,_v in self.__dict__.items():
            if _k.startswith("_") or _k in ("device"): 
                continue
            _ret.append(f"{self.device}|{_k}|{_v}")
        return "\n".join(_ret)

if __name__ == "__main__":
    import argparse
    class SmartFormatter(argparse.HelpFormatter):
        def _split_lines(self, text, width):
            if text.startswith('R|'):
                return text[2:].splitlines()  
            # this is the RawTextHelpFormatter._split_lines
            return argparse.HelpFormatter._split_lines(self, text, width)
    _checks_available = sorted(list(map(lambda x: x.split("_")[1],filter(lambda x: x.startswith("check_") or x.startswith("checklocal_"),dir(checkmk_checker)))))
    _ = lambda x: x
    _parser = argparse.ArgumentParser(
        add_help=False,
        formatter_class=SmartFormatter
    )
    _parser.add_argument("--help",action="store_true",
        help=_("show help message"))
    _parser.add_argument("--start",action="store_true",
        help=_("start the daemon"))
    _parser.add_argument("--restart",action="store_true",
        help=_("stop and restart the daemon"))
    _parser.add_argument("--stop",action="store_true",
        help=_("stop the daemon"))
    _parser.add_argument("--status",action="store_true",
        help=_("show daemon status"))
    _parser.add_argument("--nodaemon",action="store_true",
        help=_("run in foreground"))
    _parser.add_argument("--checkoutput",nargs="?",const="127.0.0.1",type=str,metavar="hostname",
        help=_("connect to [hostname]port and decrypt if needed"))
    _parser.add_argument("--update",nargs="?",const="main",type=str,metavar="branch/commitid",
        help=_("check for update"))
    _parser.add_argument("--config",type=str,dest="configfile",default=CHECKMK_CONFIG,
        help=_("path to config file"))
    _parser.add_argument("--port",type=int,default=6556,
        help=_("port checkmk_agent listen"))
    _parser.add_argument("--encrypt",type=str,dest="encrypt",
        help=_("encryption password (do not use from cmdline)"))
    _parser.add_argument("--pidfile",type=str,default="/var/run/checkmk_agent.pid",
        help=_("path to pid file"))
    _parser.add_argument("--onlyfrom",type=str,
        help=_("comma seperated ip addresses to allow"))
    _parser.add_argument("--skipcheck",type=str,
        help=_("R|comma seperated checks that will be skipped \n{0}".format("\n".join([", ".join(_checks_available[i:i+10]) for i in range(0,len(_checks_available),10)]))))
    _parser.add_argument("--debug",action="store_true",
        help=_("debug Ausgabe"))

    def _args_error(message):
        print("#"*35)
        print("checkmk_agent for opnsense")
        print(f"Version: {__VERSION__}")
        print("#"*35)
        print(message)
        print("")
        print("use --help or -h for help")
        sys.exit(1)
    _parser.error = _args_error
    args = _parser.parse_args()
    if args.configfile and os.path.exists(args.configfile):
        for _k,_v in re.findall(f"^(\w+):\s*(.*?)(?:\s+#|$)",open(args.configfile,"rt").read(),re.M):
            if _k == "port":
                args.port = int(_v)
            if _k == "encrypt" and args.encrypt == None:
                args.encrypt = _v
            if _k == "onlyfrom":
                args.onlyfrom = _v
            if _k == "skipcheck":
                args.skipcheck = _v
            if _k.lower() == "localdir":
                LOCALDIR = _v
            if _k.lower() == "plugindir":
                PLUGINSDIR = _v
            if _k.lower() == "spooldir":
                SPOOLDIR = _v

    _server = checkmk_server(**args.__dict__)
    _pid = 0
    try:
        with open(args.pidfile,"rt") as _pidfile:
            _pid = int(_pidfile.read())
    except (FileNotFoundError,IOError):
        if ISLINUX:
            _out = subprocess.check_output(["/bin/ss", "-l", "-p","-t","-n", f'sport = :{args.port}'],encoding=sys.stdout.encoding)
        else:
            _out = subprocess.check_output(["sockstat", "-l", "-p", str(args.port),"-P", "tcp"],encoding=sys.stdout.encoding)
        try:
            _pid = int(re.findall("\s(\d+)\s",_out.split("\n")[1])[0])
        except (IndexError,ValueError):
            pass
    if args.start:
        if _pid > 0:
            try:
                os.kill(_pid,0)
                sys.stderr.write(f"allready running with pid {_pid}\n")
                sys.stderr.flush()
                sys.exit(1)
            except OSError:
                pass
        _server.daemonize()

    elif args.status:
        if _pid <= 0:
            print("not running")
        else:
            try:
                os.kill(_pid,0)
                print("running")
            except OSError:
                print("not running")

    elif args.stop or args.restart:
        if _pid == 0:
            sys.stderr.write("not running\n")
            sys.stderr.flush()
            if args.stop:
                sys.exit(1)
        try:
            print("stopping")
            os.kill(_pid,signal.SIGTERM)
        except ProcessLookupError:
            if os.path.exists(args.pidfile):
                os.remove(args.pidfile)

        if args.restart:
            print("starting")
            time.sleep(3)
            _server.daemonize()

    elif args.checkoutput:
        sys.stdout.write(_server.cmkclient(**args.__dict__))
        sys.stdout.write("\n")
        sys.stdout.flush()

    elif args.debug:
        sys.stdout.write(_server.do_checks(debug=True).decode(sys.stdout.encoding))
        sys.stdout.flush()

    elif args.nodaemon:
        _server.server_start()

    elif args.update:
        import hashlib
        import difflib
        from pkg_resources import parse_version
        _github_req = requests.get(f"https://api.github.com/repos/bashclub/check-truenas/contents/truenas_checkmk_agent.py?ref={args.update}")
        if _github_req.status_code != 200:
            raise Exception(f"Github Error {_github_req.status_code}")
        _github_version = _github_req.json()
        _github_last_modified = datetime.strptime(_github_req.headers.get("last-modified"),"%a, %d %b %Y %X %Z")
        _new_script = base64.b64decode(_github_version.get("content")).decode("utf-8")
        _new_version = re.findall("^__VERSION__.*?\"([0-9.]*)\"",_new_script,re.M)
        _new_version = _new_version[0] if _new_version else "0.0.0"
        _script_location = os.path.realpath(__file__)
        _current_last_modified = datetime.fromtimestamp(int(os.path.getmtime(_script_location)))
        with (open(_script_location,"rb")) as _f:
            _content = _f.read()
        _current_sha = hashlib.sha1(f"blob {len(_content)}\0".encode("utf-8") + _content).hexdigest()
        _content = _content.decode("utf-8")
        if _current_sha == _github_version.get("sha"):
            print(f"allready up to date {_current_sha}")
            sys.exit(0)
        else:
            _version = parse_version(__VERSION__)
            _nversion = parse_version(_new_version)
            if _version == _nversion:
                print("same Version but checksums mismatch")
            elif _version > _nversion:
                print(f"ATTENTION: Downgrade from {__VERSION__} to {_new_version}")
        while True:
            try:
                _answer = input(f"Update {_script_location} to {_new_version} (y/n) or show difference (d)? ")
            except KeyboardInterrupt:
                print("")
                sys.exit(0)
            if _answer in ("Y","y","yes","j","J"):
                with open(_script_location,"wb") as _f:
                    _f.write(_new_script.encode("utf-8"))
                
                print(f"updated to Version {_new_version}")
                if _pid > 0:
                    try:
                        os.kill(_pid,0)
                        try:
                            _answer = input(f"Daemon is running (pid:{_pid}), reload and restart (Y/N)? ")
                        except KeyboardInterrupt:
                            print("")
                            sys.exit(0)
                        if _answer in ("Y","y","yes","j","J"):
                            print("stopping Daemon")
                            os.kill(_pid,signal.SIGTERM)
                            print("waiting")
                            time.sleep(5)
                            print("restart")
                            os.system(f"{_script_location} --start")
                            sys.exit(0)
                    except OSError:
                        pass
                break
            elif _answer in ("D","d"):
                for _line in difflib.unified_diff(_content.split("\n"),
                            _new_script.split("\n"),
                            fromfile=f"Version: {__VERSION__}",
                            fromfiledate=_current_last_modified.isoformat(),
                            tofile=f"Version: {_new_version}",
                            tofiledate=_github_last_modified.isoformat(),
                            n=1,
                            lineterm=""):
                    print(_line)
            else:
                break

    elif args.help:
        _isinstalled = list(filter(lambda x: x.get("command","") == f"{SCRIPTPATH} --start",checkmk_checker()._midclt("initshutdownscript.query")))
        print("#"*35)
        print("checkmk_agent for TrueNAS Scale/Core")
        print(f"Version: {__VERSION__}")
        print("#"*35)
        print("")
        print("Latest Version under https://github.com/bashclub/check-truenas")
        print("Server-side implementation for")
        print("-"*35)
        print("\t* smartdisk - install the mkp from https://github.com/bashclub/checkmk-smart plugins os-smart")
        _parser.print_help()
        print("\n")
        if _isinstalled:
            print("INSTALLED: '{command}' is installed {when} enabled:{enabled}".format(**_isinstalled[0]))
            print("\n")
        else:
            print("to install the script run the following command\n")
            print(f'midclt call initshutdownscript.create \'{{"type": "COMMAND", "command": "{SCRIPTPATH} --start", "enabled": true, "comment": "Start CheckMK-Agent", "when": "POSTINIT"}}\'')
            print("\n\n")
        print(f"The CHECKMK_BASEDIR is under {BASEDIR} (local,plugin,spool).")
        print(f"Default config file location is {args.configfile}, create it if it doesn't exist.")
        print("Config file options port,encrypt,onlyfrom,skipcheck with a colon and the value like the commandline option\n")
        print("active config:")
        print("-"*35)
        for _opt in ("port","encrypt","onlyfrom","skipcheck"):
            _val = getattr(args,_opt,None)
            if _val:
                print(f"{_opt}: {_val}")
        print("")
        
    else:
        log("no arguments")
        print("#"*35)
        print("checkmk_agent for TrueNAS")
        print(f"Version: {__VERSION__}")
        print("#"*35)
        print("use --help or -h for help")
