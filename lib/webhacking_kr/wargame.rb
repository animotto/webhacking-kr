# frozen_string_literal: true

require 'uri'
require 'net/http'

module WebhackingKR
  ##
  # Wargame
  class Wargame
    BASE_URI = 'https://webhacking.kr'
    QUERY_LOGIN = '/login.php?login'

    attr_reader :session_id
    attr_accessor :level

    def initialize(shell)
      @shell = shell

      uri = URI(BASE_URI)
      @client = Net::HTTP.new(uri.host, uri.port)
      @client.use_ssl = uri.instance_of?(URI::HTTPS)
      @session_id = nil

      @level = 1
      @levels = []
      LevelBase.successors.each { |successor| @levels << successor.new(@shell, self, @client) }
    end

    def auth(login, password)
      request = Net::HTTP::Post.new(QUERY_LOGIN)
      request.set_form_data(
        {
          'id' => login,
          'pw' => password
        }
      )
      response = @client.request(request)
      return if response.body =~ /Login Failed/

      @session_id = response['Set-Cookie']
    end

    def exec
      unless @session_id
        @shell.log('Not authenticated')
        return
      end

      level = @levels.detect { |l| l.class::LEVEL == @level }
      unless level
        @shell.log('Unknown level')
        return
      end

      level.exec
    end
  end
end
