class Dfs < Formula
  desc "Encrypted distributed filesystem CLI and service (dfscli / dfssvc)"
  homepage "https://github.com/yashiki2005/dfs"
  version "__VERSION__"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/yashiki2005/dfs/releases/download/__TAG__/dfs-__TAG__-darwin-arm64.tar.gz"
      sha256 "__SHA_DARWIN_ARM64__"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/yashiki2005/dfs/releases/download/__TAG__/dfs-__TAG__-linux-x86_64.tar.gz"
      sha256 "__SHA_LINUX_X86_64__"
    end
    on_arm do
      url "https://github.com/yashiki2005/dfs/releases/download/__TAG__/dfs-__TAG__-linux-arm64.tar.gz"
      sha256 "__SHA_LINUX_ARM64__"
    end
  end

  def install
    bin.install "dfscli"
    bin.install "dfssvc"
  end

  test do
    assert_match "dfscli", shell_output("#{bin}/dfscli --help")
    assert_match "dfssvc", shell_output("#{bin}/dfssvc --help")
  end
end
