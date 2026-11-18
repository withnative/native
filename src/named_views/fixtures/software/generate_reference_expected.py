"""Regenerate reference-expected.json from the retained package reference.

Usage (read-only on the reference; nothing is written next to it):

    python3 -I generate_reference_expected.py /path/to/armc/observed_software.py \
        > reference-expected.json

The reference file is refused unless its SHA-256 matches REFERENCE_SHA256.
Every tree below is synthetic; no corpus, gold or accuracy data is involved.
The expected values are whatever the reference returns, with one derived
mapping (FLAG_MAPPING) from its property values to the fixture's tri-state
`selected` / `disabled` fields. Nothing is hand-edited.
"""
import hashlib
import importlib.util
import json
import sys

sys.dont_write_bytecode = True

REFERENCE_SHA256 = "f4eee3b4428d860e45621a1c11df35909d8e80f61becd9e236cf2806655fd808"
REFERENCE_PATH = "longmemeval-v2/armc/observed_software.py"
FLAG_MAPPING = (
    "reference property value True (bare key) or 'True' -> true; "
    "'False' -> false; absent or any other value -> null"
)

CASES = {
    "positive": 'combobox "Priority" required\n\toption "High" selected=True\n\toption "Low"\ncombobox "Area"\n',
    # A scope whose only control has no option children (zero-option coverage).
    "zero_option": 'combobox "Area"\n',
    "tricky": (
        '[a] combobox "Dup"\n[a] combobox "Dup"\n\tmenuitem "Action"\noption "Orphan"\n'
        '\tcombobox "Nested"\n\t\toption "Inner" selected=False\n\t\toption "Unterminated\n  badindent\n'
    ),
    # P4: lexing that the reference refuses, warns on, or reads differently.
    "lex_unquoted_word": 'combobox Priority required\n\toption High selected=True\n',
    "lex_role_quote_no_separator": 'combobox"Priority"\n\toption "High"\ncombobox,"Comma"\n',
    "lex_bid_forms": (
        '[ab_1] combobox "One"\n[a-b] combobox "Dash"\n[] combobox "Empty"\n'
        '[ab]combobox "NoSpace"\n[caf\u00e9] combobox "Uni"\n[ab] \t combobox "Tabbed"\n[x]\n'
    ),
    "lex_property_tokens": (
        'combobox "C" a,,b\n\toption "O" selected = True\n\toption "P" , selected=True\n'
        '\toption "Q" selected=True,\n\toption "R" selected=\n\toption "S" selected="False"\n'
        '\toption "T" disabled=True,disabled=False\n\toption "U" selected= True\n'
        '\toption "V" selected=T"rue\n\toption "W" selected="True"x\n\toption "X" selected="True\n'
        '\toption "Y" key=\'a,b\',selected=False\n\toption "Z" 9bad,ok\n'
    ),
    "lex_label_forms": (
        'combobox "Label"suffix\ncombobox "Label" , selected=True\ncombobox\ncombobox \n'
        'combobox  "Spaced"\ncombobox "Unterminated\n'
        'combobox \'single\' disabled\ncombobox "a\\"b"\n'
    ),
    "lex_indent_gaps": '\tcombobox "IndentedFirst"\n\t\toption "Deep"\ncombobox "Root"\n\t\toption "Gap"\n\toption "Ok"\n\t\t\toption "Gap2"\n\t\toption "Back"\n',
    "lex_blank_and_markers": 'combobox "A"\n\n   \n...\n\u2026 more\n[truncated] x\ntruncated\nTRUNCATED "T"\n<truncated>\n\toption "B"\n',
    # P5: escapes, line terminators and offsets.
    "escapes": (
        'combobox "A\\u0041\\x42\\n\\/"\n\toption "\\ud83d\\ude00"\n\toption "\\ud83d"\n'
        '\toption "\\ude00"\n\toption "\\q\\u12"\n\toption "\\ud83dx"\n\toption "trail\\\\"\n\toption "\\\\u0041"\n'
        '\toption "\\ud83d\\u0041"\n\toption "\\xZZ"\n'
    ),
    "crlf_offsets": 'combobox "A"\r\n\toption "B\u00e9"\r\n\r\ncombobox "C"\r\n\toption "D"',
    "bare_cr_and_exotic_breaks": 'combobox "A"\r\toption "B"\x0b\toption "C"\x0c\toption "D"\x1c\toption "E"\x85\toption "F"\u2028\toption "G"\u2029combobox "H"\n',
    "unicode_offsets": 'combobox "caf\u00e9 \u4e2d\u6587 \U0001f600"\n\toption "\u00e9"\n\u00e9bad\n\toption "\u00fcber"\n',
    # Groups: option membership, nesting and subtree boundaries.
    "groups": (
        'combobox "Top"\n\toption "A"\n\tgroup "G"\n\t\toption "B"\n\t\tlistbox "Nested"\n\t\t\toption "C"\n\t\toption "D"\n'
        'combobox "Empty"\nlistbox "Tail"\n\toption "Z"\n'
    ),
    "groups_end_of_source": 'combobox "OnlyTree"\n\toption "A"\n\toption "B"',
}


def load_reference(path):
    with open(path, "rb") as handle:
        data = handle.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != REFERENCE_SHA256:
        sys.exit("reference sha256 %s != pinned %s" % (digest, REFERENCE_SHA256))
    spec = importlib.util.spec_from_file_location("observed_software", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def flag(props, name):
    value = props.get(name)
    if value is True or value == "True":
        return True
    if value == "False":
        return False
    return None


def case(reference, name, tree):
    projection = reference.project_tree(tree, source_ref="fixture:" + name, view_id="view-" + name)
    nodes = projection["nodes"]
    index_by_id = {n["id"]: i for i, n in enumerate(nodes)}
    out_nodes = []
    groups = []
    for node in nodes:
        evidence = node["evidence"]
        out_nodes.append({
            "role": node["role"],
            "label": node["label"],
            "source_order": node["source_order"],
            "parent": index_by_id.get(node["parent_id"]),
            "depth": node["depth"],
            "bid": node["source_bid"],
            "selected": flag(node["properties"], "selected"),
            "disabled": flag(node["properties"], "disabled"),
            "line": evidence["line_start"],
            "char_start": evidence["char_start"],
            "char_end": evidence["char_end"],
            "exact": evidence["exact"],
        })
        if node["role"] in ("combobox", "listbox"):
            read = reference.read_control_options(
                projection, label=node["label"], control_id=node["id"])
            groups.append({
                "control": node["source_order"],
                "options": [o["source_order"] for o in read["observations"]["options"]],
                "boundary": read["coverage"]["subtree_boundary"]["kind"],
            })
    cov = projection["coverage"]
    return {
        "schema": projection["schema"],
        "tree": tree,
        "tree_sha256": projection["source"]["sha256"],
        "nodes": out_nodes,
        "groups": groups,
        "coverage": {
            "unparsed_nonempty_lines": cov["unparsed_nonempty_lines"],
            "structural_warnings": cov["structural_warnings"],
            "parsed_nodes": cov["parsed_nodes"],
        },
    }


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    reference = load_reference(sys.argv[1])
    out = {
        "provenance": {
            "reference_file": REFERENCE_PATH,
            "reference_sha256": REFERENCE_SHA256,
            "reference_version": reference.VERSION,
            "generator": "src/named_views/fixtures/software/generate_reference_expected.py",
            "flag_mapping": FLAG_MAPPING,
            "offset_unit": "unicode_codepoint",
            "data": "synthetic fixtures only; no corpus, gold or accuracy data",
        },
    }
    for name, tree in CASES.items():
        out[name] = case(reference, name, tree)
    json.dump(out, sys.stdout, indent=1, ensure_ascii=True)
    sys.stdout.write("\n")


main()
