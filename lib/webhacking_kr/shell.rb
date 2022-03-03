# frozen_string_literal: true

require 'readline'

module WebhackingKR
  ##
  # Shell
  class Shell
    PROMPT = 'Webhacking.kr> '
    BANNER = <<~ENDBANNER
      _______________________

       Webhacking.kr wargame
      _______________________

    ENDBANNER

    def initialize
      @input = $stdin
      @output = $stdout
      @running = false
      @wargame = Wargame.new(self)
    end

    def log(message)
      @output.puts(message)
    end

    def run
      log(BANNER)
      @running = true
      while @running
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

        when 'l', 'level'
          if words.length < 2
            log('Specify the level')
            next
          end

          @wargame.level = words[1].to_i
          @wargame.exec

        else
          log('Unknown command')
        end
      end
    end
  end
end
