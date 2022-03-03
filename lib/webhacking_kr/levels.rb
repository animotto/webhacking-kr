# frozen_string_literal: true

module WebhackingKR
  ##
  # Level base
  class LevelBase
    @@successors = []

    class << self
      def inherited(subclass)
        super
        @@successors << subclass
      end

      def successors
        @@successors
      end
    end

    def initialize(shell, wargame, client)
      @shell = shell
      @wargame = wargame
      @client = client
    end

    def exec; end

    def get(query, headers = {})
      cookie = headers.fetch('Cookie', '')
      headers['Cookie'] = "#{@wargame.session_id}; #{cookie}"
      @client.get(query, headers)
    end
  end

  ##
  # Level 1
  class Level1 < LevelBase
    LEVEL = 1

    QUERY = '/challenge/web-01/'

    def exec
      response = get(
        QUERY,
        {'Cookie' => 'user_lv=3.5'}
      )

      if response.body =~ /old-01 Pwned/
        @shell.log('Pwned')
        return
      end

      if response.body =~ /already solved/
        @shell.log('Already solved')
        return
      end

      @shell.log('Failed')
    end
  end
end
