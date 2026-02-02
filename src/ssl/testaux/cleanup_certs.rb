###############################################################################
# Script to cleanup bad certs that prevent testing the servers with openssl   #
# 																			  #
# Copyright 2025 DigiCert Project Authors. All Rights Reserved.
# 
# DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
# - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
# - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
#   or https://www.digicert.com/master-services-agreement/
# 
# *For commercial licensing, contact DigiCert at sales@digicert.com.*
###############################################################################

def isGoodKeyUsage(certFileName, line, publicKeyAlgo)

  if (!line.match(/Digital Signature/))
    puts "#{certFileName}: Digital signature key usage missing: #{line}"
    return false
  end

  if publicKeyAlgo == "id-ecPublicKey"   # ECC certificate
    if (!line.match(/Key Agreement/))
      puts "#{certFileName}: ECC certificate with Key Agreement key usage missing: #{line}"
      return false
    end
  else # RSA certificate
    if (!line.match(/Key Encipherment/))
      puts "#{certFileName}: RSA certificate with Key Encipherment key usage missing: #{line}"
      return false
    end
  end

  return true # no problem found
end

def isBadCert( certFileName)

  certText = ""
  extension = File.extname(certFileName)
  inform = extension[1..-1].upcase
  begin
    certText = `openssl x509 -text -in #{certFileName} -inform #{inform}`
  rescue
    puts "error executing openssl"
    return false
  end

  publicKeyAlgo = nil
  nextLineIsKeyUsage = nil
  certText.each_line do |l|

    # bad if the subject CN is ssltest2.mocana.com -- we need localhost instead
    # so that server can be easily tested with regular browsers
    if l.match(/Subject:(.*)CN=ssltest2.mocana.com/)
      return true
    end

    # bad if the signature is not SHA256, SHA384 or SHA512
    m = l.match(/Signature Algorithm:\s* (.+)/)
    if m
      if (! m[1].upcase.match(/SHA-*(256|384|512)/))
        puts "#{certFileName}: Signature is not SHA2 based"
        return true
      end
    end

    # remember the publicKeyAlgo
    m = l.match(/Public Key Algorithm:\s* (.+)/)
    if m
      publicKeyAlgo = m[1]
    end

    # look for KeyUsage
    if !nextLineIsKeyUsage
      nextLineIsKeyUsage = l.match(/X509v3 Key Usage:/)
    else
      # nextLineIsKeyUsage
      return !isGoodKeyUsage(certFileName, l, publicKeyAlgo)
    end
  end
  return false # no problem found
end

Dir["./*"].each do |path|
  extension = File.extname(path).upcase
  if extension == ".PEM" || extension == ".DER"
    if isBadCert(path)
      puts "#{path} is a bad certificate"
      puts "Deleting #{path}"
      File.delete(path)
    end
  end
end
