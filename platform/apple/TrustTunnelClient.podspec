# Resolve the pod version: TT_CLIENT_VERSION env var -> git describe --tags
# --match v* -> 0.0.0-git fallback. CI sets TT_CLIENT_VERSION for the release.
def resolve_tt_client_version
  env = ENV['TT_CLIENT_VERSION']
  return env.strip unless env.nil? || env.strip.empty?

  described = `git describe --tags --match 'v*' 2>/dev/null`.strip
  return described.sub(/^v/, '') unless described.empty?

  '0.0.0-git'
end

Pod::Spec.new do |s|
  s.name         = "TrustTunnelClient"
  s.module_name  = "TrustTunnelClient"
  s.version      = resolve_tt_client_version
  s.summary      = "TrustTunnelClient Apple adapter"
  s.description  = <<-DESC
                  TrustTunnelClient adapter for macOS and iOS
                   DESC
  s.homepage     = "https://adguard.com"
  s.license      = { :type => "Apache", :file => "LICENSE" }
  s.authors      = { "AdGuard Dev Team" => "devteam@adguard.com" }
  s.ios.deployment_target = '14.0'
  s.osx.deployment_target = '10.15'
  s.source       = { :path => "." }

  s.vendored_frameworks = ["Framework/TrustTunnelClient.xcframework", "Framework/VpnClientFramework.xcframework"]
end
