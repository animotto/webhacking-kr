# frozen_string_literal: true

require 'readline'

module WebhackingKR
  ##
  # Shell
  class Shell
    PROMPT = 'webhacking.kr> '
    BANNER = <<~ENDBANNER
      _______________________

       webhacking.kr wargame
      _______________________

    ENDBANNER

    COMMANDS = {
      'login' => ['l', '<login> <password>', 'Login'],
      'status' => ['s', '', 'Show your status'],
      'challenge' => ['c', '<n>', 'Run challenge'],
      'help' => ['?', '', 'This help'],
      'quit' => ['q', '', 'Quit']
    }.freeze

    def initialize
      @input = $stdin
      @output = $stdout
      @running = false
      @wargame = Wargame.new(self)
      Readline.completion_proc = proc { |s| COMMANDS.keys.grep(/^#{s}/) }
    end

    def log(message)
      @output.puts(message)
    end

    def run
      log(BANNER)
      @running = true
      loop do
        break unless @running

        line = Readline.readline(PROMPT, true)
        unless line
          @running = false
          next
        end

        line.strip!
        if line.empty?
          Readline::HISTORY.pop
          next
        end

        words = line.split(/\s+/)
        cmd = words[0].downcase
        case cmd
        when 'q', 'quit'
          @running = false

        when 'l', 'login'
          if words.length < 3
            log('Specify login and password')
            next
          end

          unless @wargame.login(words[1], words[2])
            log('Login failed')
            next
          end

          log('Logged in')

        when 's', 'status'
          unless @wargame.session_id
            log('Not logged in')
            next
          end

          status = @wargame.status
          unless status
            log('Failed')
            next
          end

          log('Status:')
          status.each do |k, v|
            log(
              format(
                ' %<key>-15s%<value>s',
                key: k.capitalize,
                value: v
              )
            )
          end

        when 'c', 'challenge'
          if words.length < 2
            log('Specify the challenge')
            next
          end

          unless @wargame.session_id
            log('Not logged in')
            next
          end

          @wargame.challenge = words[1].to_i
          @wargame.exec

        when '?', 'help'
          log('Commands:')
          COMMANDS.each do |k, v|
            log(
              format(
                ' %<short>s %<long>-30s%<desc>s',
                short: v[0],
                long: "#{k} #{v[1]}",
                desc: v[2]
              )
            )
          end

        else
          log('Unknown command')
        end
      rescue Interrupt
        next
      end
    end
  end
end
