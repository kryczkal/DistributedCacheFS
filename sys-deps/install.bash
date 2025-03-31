#!/bin/bash

INSTALL_DEPS_ARCH_SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
INSTALL_DEPS_ARCH_SCRIPT_PATH="${INSTALL_DEPS_ARCH_SCRIPT_DIR}/$(basename "$0")"
INSTALL_DEPS_ARCH_SCRIPT_PACKAGES_TXT_FILE="${INSTALL_DEPS_ARCH_SCRIPT_DIR}/arch.txt"

source "${INSTALL_DEPS_ARCH_SCRIPT_DIR}/../scripts/utils/pretty_print.bash"
source "${INSTALL_DEPS_ARCH_SCRIPT_DIR}/../scripts/utils/helpers.bash"

help() {
  echo "${INSTALL_DEPS_ARCH_SCRIPT_PATH} --install [--verbose | -v] [--aur-helper [yay | paru | ...] | -a]"
  echo "Where:"
  echo "--install | -i - required flag to start installation"
  echo "--verbose | -v - flag to enable verbose output"
  echo "--aur-helper [yay | paru | ...] | -a - flag to specify and use an AUR helper (uses pacman by default)"
  echo "Note: this script is intended to be run on Arch-based systems"
}

run_install() {
  pretty_info "Using AUR helper: ${AUR_HELPER}"
  pretty_info "Installing dependencies"

  while IFS= read -r package || [ -n "$package" ]; do
    pretty_info "Installing ${package}"
    base_runner "Failed to install ${package}" "${VERBOSE}" sudo "${AUR_HELPER}" -S --noconfirm "${package}"
    pretty_success "Installed: ${package}"
  done < "${INSTALL_DEPS_ARCH_SCRIPT_PACKAGES_TXT_FILE}"

  pretty_success "Dependencies installed"
}

parse_args() {
  INSTALL_FOUND=false
  VERBOSE=false
  AUR_HELPER="pacman"

  while [[ $# -gt 0 ]]; do
    case $1 in
      -h|--help)
        help
        exit 0
        ;;
      -i|--install)
        INSTALL_FOUND=true
        shift
        ;;
      -a|--aur-helper)
        AUR_HELPER="$2"
        shift
        shift
        ;;
      -v|--verbose)
        VERBOSE=true
        shift
        ;;
      *)
        echo "Unknown argument: $1"
        exit 1
        ;;
    esac
  done
}

process_args() {
  if [ "$INSTALL_FOUND" = false ]; then
    dump_error "--install flag was not provided!"
  fi

  if ! command -v "${AUR_HELPER}" &> /dev/null; then
    dump_error "AUR helper ${AUR_HELPER} is not installed"
  fi
}

main() {
  parse_args "$@"
  process_args
  run_install
}

main "$@"

