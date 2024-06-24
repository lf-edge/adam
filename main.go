// ADAM API UI v 0.1
//
// Adam is the reference implementation of an LF-Edge API-compliant Controller.
//
//	Schemes: https
//	Version: 0.1.0
//	basePath: /admin
//
//	Consumes:
//	- application/json
//
//	Produces:
//	- application/json
//
// swagger:meta
package main

import (
	"github.com/lf-edge/adam/cmd"
)

func main() {
	cmd.Execute()
}
