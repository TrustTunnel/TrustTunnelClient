
Pod::Spec.new do |s|
  s.name         = "TrustTunnel"
  s.module_name  = "TrustTunnel"
  s.version      = "1.0.0"
  s.summary      = "TrustTunnel Apple adapter"
  s.description  = <<-DESC
                  TrustTunnel adapter for macOS and iOS
                   DESC
  s.homepage     = "https://adguard.com"
  s.license      = { :type => "Apache", :file => "../../LICENSE" }
  s.authors      = { "TODO" => "todo@adguard.com" }
  s.ios.deployment_target = '14.0'
  s.osx.deployment_target = '10.15'
  s.source       = { :path => "." }

  s.vendored_frameworks = ["Framework/TrustTunnel.xcframework", "Framework/VpnClientFramework.xcframework"]
end
