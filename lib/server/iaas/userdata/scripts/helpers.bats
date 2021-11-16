#!/usr/bin/env bats

load ./helpers

@test "Check my IP" {
  run MyIP
  [ "$status" -eq 0 ]
  [ "${lines[0]}" = "192.168.0.26/24" ]
}

@test "Compare" {
  run checkVersion "8.0" "7" ">"
  [ "$status" -eq 0 ]
  run checkVersion "8.0" "7.112" ">"
  [ "$status" -eq 0 ]
  run checkVersion "8.0" "8.112" "<"
  [ "$status" -eq 0 ]
  run checkVersion "8.0" "8" "="
  [ "$status" -eq 0 ]
}