//go:build !unix

package app

import "os"

// notifyReload reports false: there is no SIGHUP here, so the ruleset is
// reloaded through POST /v1/rules/reload only.
func notifyReload(chan<- os.Signal) bool { return false }
