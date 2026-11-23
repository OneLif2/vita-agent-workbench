import math
import time
import random

#mode = sys.argv[1]
sleep_t = 1

class Player():
    def __init__(self, letter):
        self.letter = letter

    def get_move(self, game):
        pass

class HumanPlayer(Player):
    def __init__(self, letter):
        super().__init__(letter)

    def get_move(self, game):
        valid_square = False
        val = None
        while not valid_square:
            global draw, Awins, Bwins, rounds
            square = input(self.letter + '\'s turn. Input move (1-9) or (q) to quit: ')
            if square == 'q':
                draw = 0
                Awins = 0
                Bwins = 0
                rounds = 0
                br_while = True
                print()
                mainMenu()
            try:
                val = int(square)    
                if val not in game.available_moves():
                    raise ValueError
                valid_square = True
            except ValueError:
                print('Invalid square. Try again.')
        return val

class RandomComputerPlayer(Player):
    def __init__(self, letter):
        super().__init__(letter)

    def get_move(self, game):
        square = random.choice(game.available_moves())
        return square

class SmartComputerPlayer(Player):
    def __init__(self, letter):
        super().__init__(letter)

    def get_move(self, game):
        if len(game.available_moves()) == 9:
            square = random.choice(game.available_moves())
        else:
            square = self.minimax(game, self.letter)['position']
        return square #return square

    def minimax(self, state, player):
        max_player = self.letter  # yourself
        other_player = 'O' if player == 'X' else 'X'

        # first we want to check if the previous move is a winner
        if state.current_winner == other_player:
            return {'position': None, 'score': 1 * (state.num_empty_squares() + 1) if other_player == max_player else -1 * (
                        state.num_empty_squares() + 1)}
        elif not state.empty_squares():
            return {'position': None, 'score': 0}

        if player == max_player:
            best = {'position': None, 'score': -math.inf}  # each score should maximize
        else:
            best = {'position': None, 'score': math.inf}  # each score should minimize
        for possible_move in state.available_moves():
            state.make_move(possible_move, player)
            sim_score = self.minimax(state, other_player)  # simulate a game after making that move

            # undo move
            state.board[possible_move] = ' '
            state.current_winner = None
            sim_score['position'] = possible_move  # this represents the move optimal next move

            if player == max_player:  # X is max player
                if sim_score['score'] > best['score']:
                    best = sim_score
            else:
                if sim_score['score'] < best['score']:
                    best = sim_score
        return best
    
class SmartComputerPlayer2(Player):
    def __init__(self, letter):
        super().__init__(letter)

    def get_move(self, game):
        rounds_ct = rounds // 2
        print(game.available_moves())
        if len(game.available_moves()) == 9:
            square = 6
    
    # working
        elif rounds_ct == 0 and (4 in game.available_moves()) == False and len(game.available_moves())==8:
            square = 5
        elif rounds_ct == 0 and (4 in game.available_moves()) == False and (2 in game.available_moves()) == False and len(game.available_moves())>=6:
            square = 9
        elif rounds_ct == 1 and (8 in game.available_moves()) == False and len(game.available_moves())==8:
            square = 5
        elif rounds_ct == 1 and (8 in game.available_moves()) == False and (4 in game.available_moves()) == False and len(game.available_moves())>=6:
            square = 3
        elif rounds_ct == 2 and (6 in game.available_moves()) == False and len(game.available_moves())==8:
            square = 5
        elif rounds_ct == 2 and (6 in game.available_moves()) == False and (8 in game.available_moves()) == False and len(game.available_moves())>=6:
            square = 1
        elif rounds_ct == 3 and (2 in game.available_moves()) == False and len(game.available_moves())==8:
            square = 5
        elif rounds_ct == 3 and (2 in game.available_moves()) == False and (6 in game.available_moves()) == False and len(game.available_moves())>=6:
            square = 7
        else:
            square = self.minimax(game, self.letter)['position']
        print("check",square)
        return square #return square

    def minimax(self, state, player):
        max_player = self.letter  # yourself
        other_player = 'O' if player == 'X' else 'X'

        # first we want to check if the previous move is a winner
        if state.current_winner == other_player:
            return {'position': None, 'score': 1 * (state.num_empty_squares() + 1) if other_player == max_player else -1 * (
                        state.num_empty_squares() + 1)}
        elif not state.empty_squares():
            return {'position': None, 'score': 0}

        if player == max_player:
            best = {'position': None, 'score': -math.inf}  # each score should maximize
        else:
            best = {'position': None, 'score': math.inf}  # each score should minimize
        for possible_move in state.available_moves():
            state.make_move(possible_move, player)
            sim_score = self.minimax(state, other_player)  # simulate a game after making that move

            # undo move
            state.board[possible_move] = ' '
            state.current_winner = None
            sim_score['position'] = possible_move  # this represents the move optimal next move

            if player == max_player:  # X is max player
                if sim_score['score'] > best['score']:
                    best = sim_score
            else:
                if sim_score['score'] < best['score']:
                    best = sim_score
        return best

#---------GAME-------GAME---------GAME---------GAME

draw = 0
Awins = 0
Bwins = 0
rounds = 0

class TicTacToe():
    
    def __init__(self):
        self.board = self.make_board()
        self.board[0] = 'W'
        self.current_winner = None
        #print('checkchecksin')
        

    @staticmethod
    def make_board():
        return [' ' for _ in range(10)]

    def print_board(self):
        for row in [self.board[i*3+1:(i+1) * 3+1] for i in range(3)]:
            print('| ' + ' | '.join(row) + ' |')

    @staticmethod
    def print_board_nums():
        # 0 | 1 | 2
        number_board = [[str(i) for i in range(j*3+1, (j+1)*3+1)] for j in range(3)]
        for row in number_board:
            print('| ' + ' | '.join(row) + ' |')
        print()

    def make_move(self, square, letter):
        #if valid mvoe, then make the mvoe (assign square to letter)
        # then return true, if invalid, return false
        if self.board[square] == ' ':
            self.board[square] = letter
            if self.winner(square, letter):
                self.current_winner = letter
            return True
        return False
    
    
#---------winner---------winner---------winner---------winner
    def winner(self, square, letter): # time = 52:16
        # winner if 3 in a row anywhere.. we have to check all of these!
        # first let's check the row
        i=3.5
        # check the row
        row_ind = math.floor(square / i)
        row = self.board[row_ind*3+1:(row_ind+1)*3+1]
        #print(self.board[0:11])
        #print('row', row)
        # if all letter in the row is same, return true
        if all([s == letter for s in row]):
            return True
        
        #check column
        col_ind = square % 3 #divided by 3
        if col_ind == 0:
            col_ind = 3
        column = [self.board[(col_ind+i*3)] for i in range(3)]
        #print('col', column)
        if all([s == letter for s in column]):
            return True
        
        # check diagonals
        # but only if the square is an even number (0,2,4,6,8)
        #these are only moves posible to win a diagonal
        if square % 2 != 0:
            diagonal1 = [self.board[i] for i in [1, 5, 9]]
             #print('diag1', diagonal1)
            if all([s == letter for s in diagonal1]):
                return True
            diagonal2 = [self.board[i] for i in [3, 5, 7]]
             #print('diag2', diagonal2)
            if all([s == letter for s in diagonal2]):
                return True
        return False

    def empty_squares(self):
        return ' ' in self.board

    def num_empty_squares(self):
        return self.board.count(' ')

    def available_moves(self):
        #return [i for i , x in enumerate(self.board) if x == " "]
        moves = []
        for (i, spot) in enumerate(self.board, start=0):
           #['x','x','o'] --> [(0, 'x'), (1,'x'), (2,'o')]
             if spot == ' ':
                moves.append(i)
        #print(moves)
        return moves
    
    def restart(self):   
        global draw, Awins, Bwins, rounds
        #print(self.current_winner)
        rounds += 1
        print('total round(s) =', rounds)
        print("%s game is draw. / " % (draw))
        print("Player X wins %s games. / " % (Awins))
        print("Player O wins %s games" % (Bwins))
        print()
        time.sleep(sleep_t*0.8) #Set time delay
        #del self.board[:]
        #print(self.board)
        

        
def play(game, x_player, o_player, print_game=True):
    global draw, Awins, Bwins, rounds
# rerounds the winner of the game(the letter) or none for a tie
    if print_game:
        game.print_board_nums()

    if rounds %2 ==0:
        letter = 'X' # starting letter
    else:
        letter = 'O' 
    #iterate while the game strill has empty squares
    #(we don't have to worry aobut winner because we'll just return that which breaks the loop)
    
#     x=game.count_draw()
#     print("check count_draw",x)
    
    while game.empty_squares():
        # get the move from the appropriate player
        if letter == 'O':
            square = o_player.get_move(game)
        else:
            square = x_player.get_move(game)
            
        # let's define a function to make a move!    
        if game.make_move(square, letter):

            if print_game:
                print(letter + ' makes a move to square {}'.format(square))
                game.print_board()
                print('') #just empty line

            # after we made our move, we need to alternate letters
            if game.current_winner:
                if print_game:
                    print(letter + ' wins! ♥♥♥♥♥♥♥♥♥♥',"\n")
                    if letter == 'X':
                        Awins += 1
                        game.restart()
                    else:
                        Bwins += 1
                        game.restart()
                return letter  # ends the loop and exits the game
            letter = 'O' if letter == 'X' else 'X'  # switches player
#             if letter == 'x':
#                 letter = 'o'
#             else:
#                 letter = 'x'

        time.sleep(sleep_t*0.5) #Set time delay

    if print_game:
        print('It\'s a tie!')
        draw += 1

    if len(game.available_moves()) == 0:
        game.restart()
       
def Prog7(br_while):
    for i in range(15):
        print()
    #br_while = br_while
    print("====== Main Menu ======")
    print("1. SmartComputerPlayer vs SmartComputerPlayer")
    print("2. SmartComputerPlayer vs RandomComputerPlayer")
    print("3. RandomComputerPlayer vs RandomComputerPlayer")
    print("4. SmartComputerPlayer vs HumanPlayer")
    print("5. HumanPlayer vs HumanPlayer")
    print("6. Quit")
    print("=======================")
    print("Enter choice: 4")
    x_player = SmartComputerPlayer2('X')
    o_player = HumanPlayer('O')
    while br_while != True :
        t = TicTacToe()
        play(t, x_player, o_player, print_game=True)
    

def mainMenu():
    print("====== Main Menu ======")
    print("1. SmartComputerPlayer vs SmartComputerPlayer")
    print("2. SmartComputerPlayer vs RandomComputerPlayer")
    print("3. RandomComputerPlayer vs RandomComputerPlayer")
    print("4. SmartComputerPlayer vs HumanPlayer")
    print("5. HumanPlayer vs HumanPlayer")
    print("6. Quit")
    print("=======================")
    br_while = False
    
    while True:
        try:
            selection = int(input("Enter choice: "))
            if selection == 1:
                x_player = SmartComputerPlayer('X')
                o_player = SmartComputerPlayer('O')
                while True:
                    t = TicTacToe()
                    play(t, x_player, o_player, print_game=True)
                break
            elif selection == 2:
                x_player = SmartComputerPlayer('X')
                o_player = RandomComputerPlayer('O')
                while True:
                    t = TicTacToe()
                    play(t, x_player, o_player, print_game=True)
                break
            elif selection == 3:
                x_player = RandomComputerPlayer('X')
                o_player = RandomComputerPlayer('O')
                while True:
                    t = TicTacToe()
                    play(t, x_player, o_player, print_game=True)
                break
            elif selection == 4:
                x_player = SmartComputerPlayer('X')
                o_player = HumanPlayer('O')
                while br_while != True :
                    t = TicTacToe()
                    play(t, x_player, o_player, print_game=True)
                break
            elif selection == 5:
                x_player = HumanPlayer('X')
                o_player = HumanPlayer('O')
                while br_while != True:
                    t = TicTacToe()
                    play(t, x_player, o_player, print_game=True)
                break
            elif selection == 6:
                print("Goodbye and save the world!")
                print()
                for i in range(6,0,-1):
                    print(i,"...")
                    time.sleep(sleep_t)
                break
            elif selection == 7:
                Prog7(br_while)

                break
            else:
                print("Invalid choice. Enter 1-3")
                mainMenu()
        except ValueError:
            print("Invalid choice. Enter 1-3")
    exit()

#main routine
if __name__ == '__main__':
    mainMenu()