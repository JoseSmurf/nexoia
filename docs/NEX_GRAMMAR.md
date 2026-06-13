# nex Grammar v1

```bnf
program        ::= spacing version_header? item*
item           ::= spacing (comment | statement) line_end?
version_header ::= "//" spacing "nex-version:" spacing version line_end
version        ::= digit+ "." digit+ "." digit+

statement      ::= use_stmt
                 | node_stmt
                 | derive_stmt
                 | attest_stmt
                 | assert_stmt
                 | act_stmt

use_stmt       ::= "use" spacing import_path
node_stmt      ::= "let" spacing ident spacing "=" spacing "node" spacing expr spacing strength
derive_stmt    ::= "let" spacing ident spacing "=" spacing ident spacing "derive" spacing ident spacing "as" spacing type
attest_stmt    ::= "attest" spacing ident spacing "with" spacing int spacing "external" spacing bool
assert_stmt    ::= "assert" spacing ident spacing ">=" spacing strength
act_stmt       ::= "act" spacing ident spacing "=" spacing action spacing "requires" spacing strength

expr           ::= int | string | ident
strength       ::= "unverifiable" | "local" | "witnessed" | "signed" | "anchored"
action         ::= "allow" | "deny" | "escalate"
type           ::= "i64" | "string"
bool           ::= "true" | "false"
import_path    ::= ident ("." ident)*
ident          ::= word
word           ::= non_space_non_syntax+
int            ::= "-"? digit+
string         ::= '"' string_char* '"'
comment        ::= "#" any* | "//" any*
spacing        ::= whitespace*
line_end       ::= "\n" | EOF
```

The version header is optional. If present, it must be the first non-empty,
non-comment line and its version must equal `1.0.0`.

Reserved keywords: `use`, `let`, `node`, `derive`, `as`, `attest`, `with`,
`external`, `assert`, `act`, `requires`, `true`, `false`, `allow`, `deny`,
`escalate`, `unverifiable`, `local`, `witnessed`, `signed`, `anchored`, `i64`,
`string`.
