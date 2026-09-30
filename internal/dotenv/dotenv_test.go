package dotenv

import (
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	src := "# comment\n" +
		"\n" +
		"PLAIN=abc123\n" +
		"export EXPORTED=yes\n" +
		"SPACED = value with spaces   # trailing comment\n" +
		"HASH_IN_VALUE=abc#def\n" +
		"SINGLE='literal $HOME \\n # not a comment'\n" +
		"DOUBLE=\"line1\\nline2 \\\"quoted\\\"\"\n" +
		"MULTI=\"-----BEGIN KEY-----\n" +
		"abc\n" +
		"-----END KEY-----\"\n" +
		"EMPTY=\n" +
		"DUP=first\r\n" +
		"DUP=second\n"
	got, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"PLAIN":         "abc123",
		"EXPORTED":      "yes",
		"SPACED":        "value with spaces",
		"HASH_IN_VALUE": "abc#def",
		"SINGLE":        `literal $HOME \n # not a comment`,
		"DOUBLE":        "line1\nline2 \"quoted\"",
		"MULTI":         "-----BEGIN KEY-----\nabc\n-----END KEY-----",
		"EMPTY":         "",
		"DUP":           "second",
	}
	gotMap := map[string]string{}
	var order []string
	for _, e := range got {
		gotMap[e.Key] = e.Value
		order = append(order, e.Key)
	}
	if !reflect.DeepEqual(gotMap, want) {
		t.Fatalf("got %#v\nwant %#v", gotMap, want)
	}
	if order[0] != "PLAIN" || order[len(order)-1] != "DUP" {
		t.Fatalf("order not kept: %v", order)
	}
}

func TestParseErrors(t *testing.T) {
	for _, src := range []string{
		"NOEQUALS\n",
		"=value\n",
		"BAD KEY=x\n",
		"OPEN=\"never closed\n",
		"OPEN='never closed\n",
	} {
		if _, err := Parse(src); err == nil {
			t.Errorf("Parse(%q) should fail", src)
		}
	}
}
