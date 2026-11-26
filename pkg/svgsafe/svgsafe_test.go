package svgsafe

import (
	"strings"
	"testing"
)

const open = `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 10 10">`

func TestAcceptsAPlainLogo(t *testing.T) {
	for name, doc := range map[string]string{
		"minimal":   open + `<path d="M0 0h10v10z" fill="#123"/></svg>`,
		"xml decl":  `<?xml version="1.0" encoding="UTF-8"?>` + "\n" + open + `<circle r="4"/></svg>`,
		"gradient":  open + `<defs><linearGradient id="g"/></defs><rect fill="url(#g)" style="fill:url(#g)"/></svg>`,
		"use local": open + `<g id="a"/><use xlink:href="#a" href="#a"/></svg>`,
		"style":     open + `<style>.a{fill:red}</style><rect class="a"/></svg>`,
		"comment":   open + `<!-- ok --></svg>`,
	} {
		if err := Validate([]byte(doc)); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
}

func TestRefusesWhatCouldRunOrFetch(t *testing.T) {
	for name, doc := range map[string]string{
		"script":          open + `<script>alert(1)</script></svg>`,
		"script upper":    open + `<SCRIPT>alert(1)</SCRIPT></svg>`,
		"foreignObject":   open + `<foreignObject><div/></foreignObject></svg>`,
		"onload":          strings.Replace(open, "<svg ", `<svg onload="x()" `, 1) + `</svg>`,
		"onclick":         open + `<rect onclick="x()"/></svg>`,
		"ONCLICK":         open + `<rect ONCLICK="x()"/></svg>`,
		"external href":   open + `<image href="https://evil.example/x.png"/></svg>`,
		"xlink href":      open + `<image xlink:href="//evil.example/x.png"/></svg>`,
		"javascript href": open + `<a href="javascript:alert(1)"><rect/></a></svg>`,
		"data href":       open + `<image href="data:image/png;base64,AA"/></svg>`,
		"url attr":        open + `<rect fill="url(https://evil.example/f)"/></svg>`,
		"url style attr":  open + `<rect style="fill:url('http://evil.example')"/></svg>`,
		"url style":       open + `<style>.a{background:url(http://evil.example)}</style></svg>`,
		"import":          open + `<style>@import "http://evil.example/a.css";</style></svg>`,
		"import escape":   open + `<style>@\69mport "x";</style></svg>`,
		"doctype":         `<!DOCTYPE svg>` + open + `</svg>`,
		"entity":          `<!DOCTYPE svg [<!ENTITY a "aaaa">]>` + open + `<text>&a;</text></svg>`,
		"stylesheet pi":   `<?xml-stylesheet href="http://evil.example/a.css"?>` + open + `</svg>`,
		"animate":         open + `<a><animate attributeName="href" to="javascript:x()"/></a></svg>`,
		"set":             open + `<a><set attributeName="href" to="javascript:x()"/></a></svg>`,
		"iframe":          open + `<iframe/></svg>`,
		"html element":    open + `<div xmlns="http://www.w3.org/1999/xhtml"/></svg>`,
		"not svg root":    `<html/>`,
		"svg wrong ns":    `<svg/>`,
		"two roots":       open + `</svg>` + open + `</svg>`,
		"text outside":    open + `</svg>junk`,
		"not xml":         `<svg xmlns="http://www.w3.org/2000/svg"><rect></svg>`,
		"empty":           ``,
	} {
		if err := Validate([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Bombs: the answer is a refusal, and it comes without reading the whole input
// into a tree.
func TestBombsAreRefused(t *testing.T) {
	deep := open + strings.Repeat("<g>", MaxDepth+1) + strings.Repeat("</g>", MaxDepth+1) + "</svg>"
	if Validate([]byte(deep)) == nil {
		t.Error("deep nesting accepted")
	}
	wide := open + strings.Repeat("<g/>", MaxElements+1) + "</svg>"
	if len(wide) <= MaxSize && Validate([]byte(wide)) == nil {
		t.Error("too many elements accepted")
	}
	big := open + `<rect fill="` + strings.Repeat("a", MaxSize) + `"/></svg>`
	if Validate([]byte(big)) == nil {
		t.Error("huge attribute accepted")
	}
	if Validate(make([]byte, MaxSize+1)) == nil {
		t.Error("oversized document accepted")
	}
	// Exactly MaxSize is within the cap.
	pad := open + "</svg>"
	pad += strings.Repeat(" ", MaxSize-len(pad))
	if err := Validate([]byte(pad)); err != nil {
		t.Errorf("a document of exactly MaxSize refused: %v", err)
	}
	// Billion laughs needs a declaration: refused before any expansion.
	laughs := `<!DOCTYPE svg [<!ENTITY a "x"><!ENTITY b "&a;&a;&a;&a;">]>` + open + `<text>&b;</text></svg>`
	if Validate([]byte(laughs)) == nil {
		t.Error("entity bomb accepted")
	}
}

func FuzzValidate(f *testing.F) {
	f.Add([]byte(open + `<path d="M0 0"/></svg>`))
	f.Add([]byte(open + `<script/></svg>`))
	f.Add([]byte(`<!DOCTYPE svg [<!ENTITY a "b">]>`))
	f.Fuzz(func(t *testing.T, b []byte) {
		// No panic, no hang; the verdict is a function of the bytes; what is
		// accepted fits the cap.
		err := Validate(b)
		if (Validate(b) == nil) != (err == nil) {
			t.Fatal("verdict differs between two calls")
		}
		if err == nil && len(b) > MaxSize {
			t.Fatalf("accepted %d bytes", len(b))
		}
	})
}
