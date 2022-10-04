import time

__author__ = "Rick Elrod"
__copyright__ = "(c) 2022 Red Hat, Inc."
__license__ = "MIT"


def test_pinentry_simple(tmux_session, gpg_home_with_secret_key, unsigned_project_with_checksum_manifest):
    """Test that we can sign a file with a pinentry program."""
    home = gpg_home_with_secret_key
    window = tmux_session.new_window(window_name="test_pinentry_simple")
    pane = window.attached_pane
    pane.resize_pane(height=24, width=80)
    pane.send_keys("unset HISTFILE")
    pane.send_keys("killall gpg-agent")
    pane.send_keys("unset ANSIBLE_SIGN_GPG_PASSPHRASE")
    pane.send_keys(f"cd {unsigned_project_with_checksum_manifest}")
    pane.send_keys(f"ansible-sign project gpg-sign --gnupg-home {home} .")
    time.sleep(2)  # Give the pinentry prompt time to show up.
    out = "\n".join(pane.cmd("capture-pane", "-p").stdout)
    assert "Passphrase: _" in out
    pane.send_keys("doYouEvenPassphrase")
    time.sleep(2)  # Give time for returning to ansible-sign and signing to finish.
    out = "\n".join(pane.cmd("capture-pane", "-p").stdout)
    assert "GPG signing successful!" in out
