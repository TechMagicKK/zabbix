//go:build linux
// +build linux

/*
** Zabbix
** Copyright (C) 2001-2021 Zabbix SIA
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
**/

package proc_custom_dir

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"

	"zabbix.com/pkg/procfs_custom_dir"
)

func read2k(filename string) (data []byte, err error) {
	fd, err := syscall.Open(filename, syscall.O_RDONLY, 0)
	if err != nil {
		return
	}
	var n int
	b := make([]byte, 2048)
	if n, err = syscall.Read(fd, b); err == nil {
		data = b[:n]
	}
	syscall.Close(fd)
	return
}

func getProcessName(procDirName string, pid string) (name string, err error) {
	var data []byte
	if data, err = read2k(fmt.Sprintf("/%s/%s/stat", procDirName, pid)); err != nil {
		return
	}
	var left, right int
	if right = bytes.LastIndexByte(data, ')'); right == -1 {
		return "", fmt.Errorf("cannot find process name ending position in %s/%s/stat", procDirName, pid)
	}
	if left = bytes.IndexByte(data[:right], '('); left == -1 {
		return "", fmt.Errorf("cannot find process name starting position in %s/%s/stat", procDirName, pid)
	}
	return string(data[left+1 : right]), nil
}

func getProcessState(procDirName string, pid string) (name string, err error) {
	var data []byte
	if data, err = read2k(fmt.Sprintf("/%s/%s/status", procDirName, pid)); err != nil {
		return
	}

	s := strings.Split(string(data), "\n")
	for _, tmp := range s {
		if strings.HasPrefix(tmp, "State:") && len(tmp) > 7 {
			return string(tmp[7:8]), nil
		}
	}

	return "", fmt.Errorf("cannot find process state %s/%s/status", procDirName, pid)
}

func getProcessUserID(procDirName string, pid string) (userid int64, err error) {
	var fi os.FileInfo
	if fi, err = os.Stat(fmt.Sprintf("%s/%s", procDirName, pid)); err != nil {
		return
	}
	return int64(fi.Sys().(*syscall.Stat_t).Uid), nil
}

func getProcessCmdline(procDirName string, pid string, flags int) (arg0 string, cmdline string, err error) {
	var data []byte
	if data, err = procfs_custom_dir.ReadAll(fmt.Sprintf("%s/%s/cmdline", procDirName, pid)); err != nil {
		return
	}

	if flags&procInfoName != 0 {
		if end := bytes.IndexByte(data, 0); end != -1 {
			if pos := bytes.LastIndexByte(data[:end], '/'); pos != -1 {
				arg0 = string(data[pos+1 : end])
			} else {
				arg0 = string(data[:end])
			}
		} else {
			arg0 = string(data)
		}
	}

	for i := 0; i < len(data); i++ {
		if data[i] == 0 {
			data[i] = ' '
		}
	}

	if len(data) != 0 && data[len(data)-1] == ' ' {
		data = data[:len(data)-1]
	}

	return arg0, string(data), nil
}

func (p *Plugin) getProcCpuUtil(procDirName string, pid int64, stat *cpuUtil) {
	var data []byte
	if data, stat.err = read2k(fmt.Sprintf("/%s/%d/stat", procDirName, pid)); stat.err != nil {
		return
	}
	var pos int
	if pos = bytes.LastIndexByte(data, ')'); pos == -1 || len(data[pos:]) < 2 {
		stat.err = fmt.Errorf("cannot find CPU statistic starting position in %s/%d/stat", procDirName, pid)
		return
	}
	stats := bytes.Split(data[pos+2:], []byte{' '})
	if len(stats) < 20 {
		stat.err = fmt.Errorf("cannot parse CPU statistics in %s/%d/stat", procDirName, pid)
		return
	}
	if stat.utime, stat.err = strconv.ParseUint(string(stats[11]), 10, 64); stat.err != nil {
		return
	}
	if stat.stime, stat.err = strconv.ParseUint(string(stats[12]), 10, 64); stat.err != nil {
		return
	}
	if stat.started, stat.err = strconv.ParseUint(string(stats[19]), 10, 64); stat.err != nil {
		return
	}
}

func getProcesses(procDirName string, flags int) (processes []*procInfo, err error) {
	var entries []os.FileInfo
	f, err := os.Open(fmt.Sprintf("%s", procDirName))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	for entries, err = f.Readdir(1); err != io.EOF; entries, err = f.Readdir(1) {
		if err != nil {
			return nil, err
		}

		if len(entries) < 1 || !entries[0].IsDir() {
			continue
		}

		var pid int64
		var tmperr error
		if pid, tmperr = strconv.ParseInt(entries[0].Name(), 10, 64); tmperr != nil {
			continue
		}
		info := &procInfo{pid: pid}
		if flags&procInfoName != 0 {
			if info.name, tmperr = getProcessName(procDirName, entries[0].Name()); tmperr != nil {
				impl.Debugf("cannot get process %s name: %s", entries[0].Name(), tmperr)
				continue
			}
		}
		if flags&procInfoUser != 0 {
			if info.userid, tmperr = getProcessUserID(procDirName, entries[0].Name()); tmperr != nil {
				impl.Debugf("cannot get process %s user id: %s", entries[0].Name(), tmperr)
				continue
			}
		}
		if flags&procInfoCmdline != 0 {
			if info.arg0, info.cmdline, tmperr = getProcessCmdline(procDirName, entries[0].Name(), flags); tmperr != nil {
				impl.Debugf("cannot get process %s command line: %s", entries[0].Name(), tmperr)
				continue
			}
		}
		if flags&procInfoState != 0 {
			if info.state, tmperr = getProcessState(procDirName, entries[0].Name()); tmperr != nil {
				impl.Debugf("cannot get process %s state: %s", entries[0].Name(), tmperr)
				continue
			}
		}

		processes = append(processes, info)
	}

	return processes, nil
}
