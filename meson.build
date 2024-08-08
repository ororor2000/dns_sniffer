project('dns_sniffer', 'c', version: '0.1.0')

# Check for libnetfilter_log dependency
netfilter_log_dep = dependency('libnetfilter_log', required: true)

# Include directories
firewall_inc = include_directories('firewall/include')
dns_sniffer_inc = include_directories('dns_sniffer/include')

lib_c_args = ['-fPIC', '-Wno-error']

# Firewall library
firewall_lib = shared_library('firewall', 
  'firewall/src/firewall.c',
  include_directories: firewall_inc,
  install: false,
  build_by_default: true,
  c_args: lib_c_args
)

# DNS Sniffer library
dns_sniffer_lib = shared_library('dns_sniffer', 
  'dns_sniffer/src/dns_sniffer.c',
  include_directories: dns_sniffer_inc,
  dependencies: netfilter_log_dep,
  install: false,
  build_by_default: true,
  c_args: lib_c_args
)

# Main executable
executable('main.out', 
  'main.c',
  include_directories: [firewall_inc, dns_sniffer_inc],
  link_with: [firewall_lib, dns_sniffer_lib],
  dependencies: netfilter_log_dep,
  install: false,
  build_by_default: true,
  c_args: ['-Wno-error'],
  install: true,
  install_dir: meson.current_source_dir(),
  link_args: [
    '-L' + meson.current_build_dir(),
    '-L' + meson.current_build_dir() + '/firewall',
    '-L' + meson.current_build_dir() + '/dns_sniffer'
  ]
)