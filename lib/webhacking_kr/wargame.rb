# frozen_string_literal: true

module WebhackingKR
  ##
  # Wargame
  class Wargame
    attr_accessor :level

    def initialize(shell)
      @shell = shell
      @level = 1
      @levels = []
      LevelBase.successors.each { |successor| @levels << successor.new(@shell) }
    end

    def exec
      level = @levels.detect { |l| l.class::LEVEL == @level }
      unless level
        @shell.log('Unknown level')
        return
      end

      level.exec
    end
  end
end
