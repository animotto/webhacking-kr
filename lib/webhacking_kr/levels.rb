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

    def initialize(shell)
      @shell = shell
    end

    def exec; end
  end

  ##
  # Level 1
  class Level1 < LevelBase
    LEVEL = 1

    def exec; end
  end
end
