require 'socket'
require 'openssl'
require 'forwardable'
require 'stringio'

module Grocer
  class SSLConnection
    extend Forwardable
    def_delegators :@ssl, :write, :read

    attr_accessor :certificate, :passphrase, :gateway, :port

    def initialize(options = {})
      options.each do |key, val|
        send("#{key}=", val)
      end
    end

    def connected?
      !@ssl.nil?
    end

    def key_and_cert_from_options
      case certificate
      when Hash
        if certificate['p12'] || certificate[:p12] || certificate['p12_file'] || certificate[:p12_file]
          pkcs12_data = certificate['p12'] || certificate[:p12] ||
            File.read(certificate['p12_file'] || certificate[:p12_file])
          pkcs12 = OpenSSL::PKCS12.new(pkcs12_data, passphrase)

          [pkcs12.key, pkcs12.certificate]
        elsif certificate['pem'] || certificate[:pem] || certificate['pem_file'] || certificate[:pem_file]
          pem_data = certificate['pem'] || certificate[:pem] ||
            File.read(certificate['pem_file'] || certificate[:pem_file])
            
          [OpenSSL::PKey::RSA.new(pem_data, passphrase), OpenSSL::X509::Certificate.new(pem_data)]
        end
      else
        if certificate.respond_to?(:read)
          cert_data = certificate.read
          certificate.rewind if certificate.respond_to?(:rewind)
        else
          cert_data = File.read(certificate)
        end

        [OpenSSL::PKey::RSA.new(cert_data, passphrase), OpenSSL::X509::Certificate.new(cert_data)]
      end
    end

    def connect
      context = OpenSSL::SSL::SSLContext.new
      context.key, context.cert = key_and_cert_from_options

      @sock            = TCPSocket.new(gateway, port)
      @sock.setsockopt   Socket::SOL_SOCKET, Socket::SO_KEEPALIVE, true
      @ssl             = OpenSSL::SSL::SSLSocket.new(@sock, context)
      @ssl.sync        = true
      @ssl.connect
    end

    def disconnect
      @ssl.close if @ssl
      @ssl = nil

      @sock.close if @sock
      @sock = nil
    end

    def reconnect
      disconnect
      connect
    end
  end
end
