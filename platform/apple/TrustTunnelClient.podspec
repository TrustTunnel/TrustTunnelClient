
Pod::Spec.new do |s|
  s.name         = "TrustTunnelClient"
  s.module_name  = "TrustTunnelClient"
  s.version      = "0.99.54"
  s.summary      = "TrustTunnelClient Apple adapter"
  s.description  = <<-DESC
                  TrustTunnelClient adapter for macOS and iOS
                   DESC
  s.homepage     = "https://adguard.com"
  s.license      = { :type => "Apache", :file => "LICENSE" }
  s.authors      = { "AdGuard Dev Team" => "devteam@adguard.com" }
  s.ios.deployment_target = '14.0'
  s.osx.deployment_target = '10.15'
  s.source       = { :http => "https://github.com/TrustTunnel/TrustTunnelClient/releases/download/v#{s.version.to_s}-apple/TrustTunnelClient-apple-#{s.version.to_s}.zip" }

  s.vendored_frameworks = ["TrustTunnelClient.xcframework", "VpnClientFramework.xcframework"]
end
