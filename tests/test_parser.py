"""The parser: shapes, continuations, runas, tags, offsets."""

from __future__ import annotations

from helpers import app_from

from sudolint.parser import looks_like_sudoers, parse_item


def test_continuation_joins_physical_lines():
    app = app_from("ops ALL = /usr/bin/htop \\\n  --verbose\n")
    assert len(app.specs) == 1
    assert app.specs[0].lineno == 1
    items = app.specs[0].items
    assert items[0].command == "/usr/bin/htop"
    assert "--verbose" in items[0].args


def test_comments_and_blank_lines_are_ignored():
    app = app_from("# a comment\n\n   \nops ALL = /usr/bin/id\n")
    assert app.specs and len(app.defaults) == 0 and len(app.directives) == 0


def test_include_and_includedir_are_directives():
    app = app_from("#include /etc/sudoers.local\n#includedir /etc/sudoers.d\n")
    assert [d.kind for d in app.directives] == ["include", "includedir"]
    assert app.directives[1].target == "/etc/sudoers.d"


def test_alias_definitions_are_stored_by_type():
    app = app_from(
        "User_Alias OPS = %ops, deploy\nHost_Alias WEB = web1, web2\nCmnd_Alias SVC = /usr/bin/systemctl restart app\n"
    )
    assert set(app.aliases) == {"User_Alias", "Host_Alias", "Cmnd_Alias"}
    assert app.aliases["User_Alias"]["OPS"].members == ["%ops", "deploy"]
    assert app.aliases["Cmnd_Alias"]["SVC"].members == ["/usr/bin/systemctl restart app"]


def test_duplicate_alias_is_recorded_as_a_note():
    app = app_from("Cmnd_Alias DUP = /usr/bin/htop\nCmnd_Alias DUP = /usr/bin/top\n")
    assert len(app.notes) == 1
    assert "line 2" in app.notes[0] and "first at line 1" in app.notes[0]


def test_runas_users_and_groups_split_on_colon():
    app = app_from("ops ALL = (deploy:docker) /usr/bin/docker ps\n")
    item = app.specs[0].items[0]
    assert item.runas_users == ["deploy"]
    assert item.runas_groups == ["docker"]


def test_tags_are_collected():
    app = app_from("ops ALL = NOPASSWD: SETENV: /usr/bin/systemctl restart app\n")
    item = app.specs[0].items[0]
    assert item.tags == {"NOPASSWD", "SETENV"}
    assert item.has_nopasswd and item.has_setenv


def test_digest_prefix_is_recorded_and_stripped():
    digest = "sha256:" + "ab" * 32
    app = app_from(f"ops ALL = {digest} /usr/bin/htop\n")
    item = app.specs[0].items[0]
    assert item.digest == digest
    assert item.command == "/usr/bin/htop"


def test_empty_args_form_is_detected():
    app = app_from('ops ALL = /usr/bin/last ""\n')
    item = app.specs[0].items[0]
    assert item.args_empty is True
    assert item.args == ""


def test_all_and_alias_detection():
    app = app_from("ops ALL = ALL, TOOLS, /usr/bin/id\n")
    items = app.specs[0].items
    assert items[0].is_all is True
    assert items[1].is_alias is True and items[1].alias_name == "TOOLS"
    assert items[2].is_alias is False


def test_second_spec_after_top_level_colon():
    app = app_from("ops ALL = /usr/bin/a : deploy ALL = /usr/bin/b\n")
    assert len(app.specs) == 2
    assert app.specs[0].users == ["ops"]
    assert app.specs[1].users == ["deploy"]


def test_runas_colon_does_not_split_the_spec():
    app = app_from("ops ALL = (root:wheel) /usr/bin/a, /usr/bin/b\n")
    assert len(app.specs) == 1
    assert len(app.specs[0].items) == 2


def test_malformed_lines_are_recorded_with_line_numbers():
    app = app_from("this line has no equals sign\nops ALL = /usr/bin/id\n")
    assert len(app.errors) == 1
    assert app.errors[0].startswith("line 1:")


def test_defaults_qualifiers_are_parsed():
    app = app_from(
        "Defaults@webserver timestamp_timeout=5\n"
        'Defaults:ops env_keep += "COLORS"\n'
        'Defaults!adm secure_path="/usr/sbin:/usr/bin"\n'
        "Defaults>root !requiretty\n"
    )
    kinds = [(d.host_qualifier, d.user_qualifier, d.runas_qualifier) for d in app.defaults]
    assert kinds[0] == (["webserver"], [], [])
    assert kinds[1] == ([], ["ops"], [])
    assert kinds[2] == ([], ["adm"], [])
    assert kinds[3] == ([], [], ["root"])
    assert app.defaults[1].params == [("env_keep", "+=", "COLORS")]


def test_defaults_negation_is_recorded():
    app = app_from("Defaults !env_reset\n")
    assert app.defaults[0].negated_names == {"env_reset"}
    assert app.defaults[0].params == [("env_reset", "", "")]


def test_byte_offsets_point_at_the_command_token():
    text = "# a comment\nops ALL = /bin/bash\n"
    app = app_from(text)
    expected = text.index("/bin/bash")
    assert app.specs[0].items[0].offset == expected
    assert app.specs[0].items[0].length == len("/bin/bash")


def test_line_offsets_cover_every_logical_line():
    app = app_from("# c\nDefaults !requiretty\nops ALL = /usr/bin/id\n")
    assert app.line_offsets == {1: 0, 2: 4, 3: 25}


def test_continuation_offset_anchors_on_the_first_physical_line():
    text = "Defaults !requiretty \\\n    !use_pty\nops ALL = /usr/bin/id\n"
    app = app_from(text)
    assert app.line_offsets[1] == 0
    # The joined line is logical line 1; the next logical line starts at
    # physical line 3, after both physical lines' bytes.
    assert 2 not in app.line_offsets
    assert app.line_offsets[3] == len("Defaults !requiretty \\\n    !use_pty\n")


def test_parse_item_standalone():
    item = parse_item("NOPASSWD: /usr/bin/less /var/log/*")
    assert item.has_nopasswd and item.command == "/usr/bin/less" and "*" in item.args


def test_looks_like_sudoers_positive_and_negative():
    assert looks_like_sudoers("Defaults !requiretty\n")
    assert looks_like_sudoers("ops ALL = /usr/bin/id\n")
    assert looks_like_sudoers("Cmnd_Alias TOOLS = /usr/bin/htop\n")
    assert not looks_like_sudoers("just some prose\n")
    assert not looks_like_sudoers("")
