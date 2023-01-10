package syslog

import (
	"github.com/vela-security/vela-public/assert"
	"github.com/vela-security/vela-public/export"
	"github.com/vela-security/vela-public/lua"
	"reflect"
)

const (
	RFC3164 int = iota + 1
	RFC5424
	RFC6587
	Automatic
)

var syslogTypeOf = reflect.TypeOf((*server)(nil)).String()
var xEnv assert.Environment

func newLuaSyslogS(L *lua.LState) int {
	cfg := newConfig(L)
	proc := L.NewProc(cfg.name, syslogTypeOf)
	if proc.IsNil() {
		proc.Set(newSyslogS(cfg))
		goto done
	}
	proc.Data.(*server).cfg = cfg

done:
	L.Push(proc)
	return 1
}

func WithEnv(env assert.Environment) {
	xEnv = env
	uv := lua.NewUserKV()
	uv.Set("RFC3164", lua.LNumber(RFC3164))
	uv.Set("RFC5424", lua.LNumber(RFC5424))
	uv.Set("RFC6587", lua.LNumber(RFC6587))
	uv.Set("AUTO", lua.LNumber(Automatic))
	xEnv.Set("syslog", export.New("vela.syslog.export", export.WithTable(uv), export.WithFunc(newLuaSyslogS)))
}
