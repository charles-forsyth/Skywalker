import sys

import pytest

from skywalker.main import main


def test_main_no_arguments(mocker):
    """Test that running skywalker with no arguments raises SystemExit."""
    mocker.patch.object(sys, "argv", ["skywalker"])

    # We want to catch the SystemExit raised by parser.error
    with pytest.raises(SystemExit):
        main()


def test_main_api_key_audit_no_scope(mocker):
    """Test that --api-key-audit without scoping raises SystemExit."""
    mocker.patch.object(sys, "argv", ["skywalker", "--api-key-audit"])

    # Catch SystemExit and verify error output if possible
    with pytest.raises(SystemExit):
        main()


def test_main_model_audit_no_scope(mocker):
    """Test that --model-audit without scoping raises SystemExit."""
    mocker.patch.object(sys, "argv", ["skywalker", "--model-audit"])

    with pytest.raises(SystemExit):
        main()


def test_main_find_zombies_no_scope(mocker):
    """Test that --find-zombies without scoping raises SystemExit."""
    mocker.patch.object(sys, "argv", ["skywalker", "--find-zombies"])

    with pytest.raises(SystemExit):
        main()


def test_main_api_key_audit_with_project(mocker):
    """Test that --api-key-audit with --project-id successfully dispatches."""
    mocker.patch.object(
        sys, "argv", ["skywalker", "--api-key-audit", "--project-id", "test-project"]
    )

    mock_run = mocker.patch("skywalker.modes.apikeys.run_api_key_audit")

    main()

    mock_run.assert_called_once()
    args = mock_run.call_args[0][0]
    assert args.api_key_audit is True
    assert args.project_id == "test-project"
    assert args.all_projects is False


def test_main_api_key_audit_with_all_projects(mocker):
    """Test that --api-key-audit with --all-projects successfully dispatches."""
    mocker.patch.object(sys, "argv", ["skywalker", "--api-key-audit", "--all-projects"])

    mock_run = mocker.patch("skywalker.modes.apikeys.run_api_key_audit")

    main()

    mock_run.assert_called_once()
    args = mock_run.call_args[0][0]
    assert args.api_key_audit is True
    assert args.project_id is None
    assert args.all_projects is True


def test_main_model_audit_with_project(mocker):
    """Test that --model-audit with --project-id successfully dispatches."""
    mocker.patch.object(
        sys, "argv", ["skywalker", "--model-audit", "--project-id", "test-project"]
    )

    mock_run = mocker.patch("skywalker.modes.modelusage.run_model_audit")

    main()

    mock_run.assert_called_once()
    args = mock_run.call_args[0][0]
    assert args.model_audit is True
    assert args.project_id == "test-project"
    assert args.all_projects is False


def test_main_model_audit_with_all_projects(mocker):
    """Test that --model-audit with --all-projects successfully dispatches."""
    mocker.patch.object(sys, "argv", ["skywalker", "--model-audit", "--all-projects"])

    mock_run = mocker.patch("skywalker.modes.modelusage.run_model_audit")

    main()

    mock_run.assert_called_once()
    args = mock_run.call_args[0][0]
    assert args.model_audit is True
    assert args.project_id is None
    assert args.all_projects is True


def test_main_find_zombies_with_project(mocker):
    """Test that --find-zombies with --project-id successfully dispatches."""
    mocker.patch.object(
        sys, "argv", ["skywalker", "--find-zombies", "--project-id", "test-project"]
    )

    mock_run = mocker.patch("skywalker.modes.zombies.run_zombie_hunt")

    main()

    mock_run.assert_called_once()
    args = mock_run.call_args[0][0]
    assert args.find_zombies is True
    assert args.project_id == "test-project"
    assert args.all_projects is False


def test_main_find_zombies_with_all_projects(mocker):
    """Test that --find-zombies with --all-projects successfully dispatches."""
    mocker.patch.object(sys, "argv", ["skywalker", "--find-zombies", "--all-projects"])

    mock_run = mocker.patch("skywalker.modes.zombies.run_zombie_hunt")

    main()

    mock_run.assert_called_once()
    args = mock_run.call_args[0][0]
    assert args.find_zombies is True
    assert args.project_id is None
    assert args.all_projects is True
