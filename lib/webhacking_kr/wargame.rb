# frozen_string_literal: true

require 'uri'
require 'net/http'

module WebhackingKR
  ##
  # Wargame
  class Wargame
    BASE_URI = 'https://webhacking.kr'
    QUERY_LOGIN = '/login.php?login'
    QUERY_CHALLENGE = '/chall.php'
    QUERY_AUTH = '/auth.php'

    attr_reader :session_id, :challenges
    attr_accessor :user_id, :password, :challenge

    def initialize(shell)
      @shell = shell

      @user_id = ENV['WEBHACK_KR_USERID']
      @password = ENV['WEBHACK_KR_PASSWORD']

      uri = URI(BASE_URI)
      @client = Net::HTTP.new(uri.host, uri.port)
      @client.use_ssl = uri.instance_of?(URI::HTTPS)
      @session_id = nil

      @challenge = 1
      @challenges = []
      ChallengeBase.successors.each { |successor| @challenges << successor.new(@shell, self, @client) }
    end

    def login
      request = Net::HTTP::Post.new(QUERY_LOGIN)
      request.set_form_data(
        {
          'id' => @user_id,
          'pw' => @password
        }
      )
      response = @client.request(request)
      return if response.body =~ /Login Failed/

      @session_id = response['Set-Cookie']
    end

    def status
      response = @client.get(
        QUERY_CHALLENGE,
        { 'Cookie' => @session_id }
      )
      match = /userid : (\S+), score : (\d+)/.match(response.body)
      return unless match

      {
        login: match[1],
        score: match[2]
      }
    end

    def exec
      challenge = @challenges.detect { |l| l.class::CHALLENGE == @challenge }
      unless challenge
        @shell.log('Unknown challenge')
        return
      end

      challenge.exec
    end
  end
end
