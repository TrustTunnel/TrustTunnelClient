
Pod::Spec.new do |s|
  s.name         = "TrustTunnelClient"
  s.module_name  = "TrustTunnelClient"
  s.version      = "0.99.21"
  s.summary      = "TrustTunnelClient Apple adapter"
  s.description  = <<-DESC
                  TrustTunnelClient adapter for macOS and iOS
                   DESC
  s.homepage     = "https://adguard.com"
  s.license      = { :type => "Apache", :file => "LICENSE" }
  s.authors      = { "TODO" => "todo@adguard.com" }
  s.ios.deployment_target = '14.0'
  s.osx.deployment_target = '10.15'
  s.source       = { :http => "http://localhost:8000/TrustTunnelClient-apple-#{s.version.to_s}.zip" }

  s.vendored_frameworks = ["TrustTunnelClient.xcframework", "VpnClientFramework.xcframework"]
end
