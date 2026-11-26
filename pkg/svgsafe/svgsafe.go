// Package svgsafe decides whether an SVG image is safe to show: a logo a server
// publishes, which a client downloads and must re-validate itself, and which a
// browser may be pointed at directly.
//
// It is an ALLOW-nothing-active validator, not a sanitiser: an image that holds
// anything that could run or fetch is refused whole, never edited.
//
// Refused: a document type declaration or entity (DOCTYPE, ENTITY: entity
// expansion), processing instructions other than the XML declaration
// (xml-stylesheet), <script>, <foreignObject>, embedded documents
// (iframe, embed, object, audio, video, canvas), animation elements that can
// rewrite an attribute (set, animate, animateTransform, animateMotion), event
// attributes (on*), any href / xlink:href that does not start with "#", any
// "javascript:" or "data:" value, any url() that does not start with "#", an
// @import in a style, nesting deeper than MaxDepth, more than MaxElements
// elements, and a document larger than MaxSize.
package svgsafe

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Limits. MaxSize: a logo is a few KiB of paths; 64 KiB leaves room for a
// detailed one and bounds both the download and the work of the parser.
const (
	MaxSize     = 64 << 10
	MaxDepth    = 32
	MaxElements = 4000
)

const svgNS = "http://www.w3.org/2000/svg"

var forbiddenElements = map[string]bool{
	"script": true, "foreignobject": true, "iframe": true, "embed": true,
	"object": true, "audio": true, "video": true, "canvas": true,
	"set": true, "animate": true, "animatetransform": true, "animatemotion": true,
	"handler": true, "listener": true,
}

// Validate returns nil when b is a well-formed SVG document that holds nothing
// active and refers to nothing outside itself.
func Validate(b []byte) error {
	if len(b) > MaxSize {
		return fmt.Errorf("svg: %d bytes, more than the %d allowed", len(b), MaxSize)
	}
	dec := xml.NewDecoder(bytes.NewReader(b))
	dec.Strict = true
	dec.Entity = nil // the five predefined entities only
	depth, elements, roots := 0, 0, 0
	inStyle := 0
	for tokens := 0; ; tokens++ {
		// A bound, not an argument: every token consumes at least one byte, so
		// more tokens than bytes means the decoder is repeating itself (it
		// returns the same syntax error for ever).
		if tokens > len(b) {
			return errors.New("svg: the decoder made no progress")
		}
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("svg: not well-formed XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.Directive:
			return errors.New("svg: a DOCTYPE or ENTITY declaration is refused")
		case xml.ProcInst:
			if t.Target != "xml" {
				return fmt.Errorf("svg: processing instruction <?%s?> is refused", t.Target)
			}
		case xml.StartElement:
			depth++
			elements++
			if depth > MaxDepth {
				return fmt.Errorf("svg: nested deeper than %d", MaxDepth)
			}
			if elements > MaxElements {
				return fmt.Errorf("svg: more than %d elements", MaxElements)
			}
			if depth == 1 {
				roots++
				// A second root is counted here and refused after the loop; the
				// namespace of every element, this one included, is checked below.
				if t.Name.Local != "svg" {
					return errors.New("svg: the root element must be <svg>")
				}
			}
			name := strings.ToLower(t.Name.Local)
			if forbiddenElements[name] {
				return fmt.Errorf("svg: <%s> is refused", t.Name.Local)
			}
			if t.Name.Space != svgNS {
				return fmt.Errorf("svg: element <%s> is not in the SVG namespace", t.Name.Local)
			}
			if name == "style" {
				inStyle++
			}
			for _, a := range t.Attr {
				if err := checkAttr(a); err != nil {
					return err
				}
			}
		case xml.EndElement:
			depth--
			if strings.EqualFold(t.Name.Local, "style") {
				inStyle--
			}
		case xml.CharData:
			if inStyle > 0 {
				if err := checkCSS(string(t)); err != nil {
					return err
				}
			} else if depth == 0 && len(bytes.TrimSpace(t)) > 0 {
				return errors.New("svg: text outside the root element")
			}
		}
	}
	if roots != 1 {
		return fmt.Errorf("svg: exactly one <svg> root element is required, found %d", roots)
	}
	return nil
}

func checkAttr(a xml.Attr) error {
	name := strings.ToLower(a.Name.Local)
	if strings.HasPrefix(name, "on") {
		return fmt.Errorf("svg: event attribute %q is refused", a.Name.Local)
	}
	v := strings.TrimSpace(a.Value)
	if name == "href" {
		if !strings.HasPrefix(v, "#") {
			return fmt.Errorf("svg: %s=%q refers outside the image", a.Name.Local, truncate(v))
		}
	}
	lv := strings.ToLower(v)
	if strings.Contains(lv, "javascript:") || strings.Contains(lv, "data:") {
		return fmt.Errorf("svg: attribute %q holds a javascript: or data: reference", a.Name.Local)
	}
	if name == "style" {
		return checkCSS(v)
	}
	return checkURLs(v)
}

// checkCSS refuses @import and any url() that is not a fragment reference.
func checkCSS(s string) error {
	l := strings.ToLower(s)
	if strings.Contains(l, "@import") {
		return errors.New("svg: @import in a style is refused")
	}
	if strings.Contains(l, "expression(") || strings.Contains(l, "behavior:") || strings.Contains(l, "-moz-binding") {
		return errors.New("svg: active CSS is refused")
	}
	if strings.Contains(l, "\\") { // CSS escapes can spell url( and @import
		return errors.New("svg: a CSS escape is refused")
	}
	return checkURLs(s)
}

// checkURLs refuses every url(...) whose argument does not start with "#".
func checkURLs(s string) error {
	l := strings.ToLower(s)
	for {
		i := strings.Index(l, "url(")
		if i < 0 {
			return nil
		}
		rest := strings.TrimLeft(l[i+4:], " \t\r\n'\"")
		if !strings.HasPrefix(rest, "#") {
			return fmt.Errorf("svg: url(%s…) refers outside the image", truncate(rest))
		}
		l = l[i+4:]
	}
}

func truncate(s string) string {
	if len(s) > 40 {
		return s[:40] + "…"
	}
	return s
}
