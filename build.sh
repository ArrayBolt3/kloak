#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## CodeQL manual build wrapper (CodeQL build-mode: manual). Installs
## the build-dep packages a fresh ubuntu-latest runner is missing,
## then invokes the upstream Makefile via 'make'. The Makefile is
## the single source of truth for hardening flags - the same
## invocation runs at package build time via debian/rules.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C
set -o xtrace

## style-ok: allow-apt-get -- runs on a stock GitHub runner, where the
## apt-get-noninteractive wrapper does not exist.
sudo --non-interactive apt-get update --error-on=any
sudo --non-interactive apt-get install --yes --no-install-recommends \
  libevdev2 libevdev-dev libinput10 libinput-dev libwayland-client0 \
  libwayland-dev libxkbcommon0 libxkbcommon-dev libcap2 libcap-dev pkg-config

make
