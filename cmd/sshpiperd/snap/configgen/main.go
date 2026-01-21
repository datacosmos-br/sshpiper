package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"strings"
)

func main() {

	configs := map[string]string{
		"sshpiperd":  "../../main.go",
		"workingdir": "../../../../plugin/workingdir/main.go",
		"yaml":       "../../../../plugin/yaml/main.go",
		"fixed":      "../../../../plugin/fixed/main.go",
		"failtoban":  "../../../../plugin/failtoban/main.go",
	}

	for k, v := range configs {
		extractFlags(k, v)
	}
}

func extractFlags(namespace, filePath string) {
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if cerr := file.Close(); cerr != nil {
			log.Printf("failed to close file: %v", cerr)
		}
	}()

	fset := token.NewFileSet()

	node, err := parser.ParseFile(fset, filePath, file, parser.AllErrors)
	if err != nil {
		log.Fatal(err)
	}

	ast.Inspect(node, func(n ast.Node) bool {

		if cl, ok := n.(*ast.CompositeLit); ok {

			if t, ok := cl.Type.(*ast.SelectorExpr); ok {

				o, ok := t.X.(*ast.Ident)
				if !ok {
					return true
				}

				if o.Name != "cli" {
					return true
				}

				if !strings.HasSuffix(t.Sel.Name, "Flag") {
					return true
				}

				var flagName string
				var flagDesc string

				for _, v := range cl.Elts {
					if kv, ok := v.(*ast.KeyValueExpr); ok {

						switch kv.Key.(*ast.Ident).Name {
						case "Name":
							flagName = strings.Trim(kv.Value.(*ast.BasicLit).Value, " \"")
						case "Usage":
							flagDesc = strings.Trim(kv.Value.(*ast.BasicLit).Value, " \"")
						}
					}
				}

				// Write flag documentation to stdout for snap configuration generation
				// This is intentional stdout output for snap configuration, not debug code
				if _, err := fmt.Fprintf(os.Stdout, "%v.%v %v\n", namespace, flagName, flagDesc); err != nil {
					log.Printf("failed to output flag documentation: %v", err)
				}
			}
		}
		return true
	})
}
