
# Function to apply formatting and color to text
def colorize_text(text, color, format=None):
    color = color.lower()
    if format is not None:
        format = format.lower()

    # Define ANSI color and formatting codes
    colors = {
        'black': '\033[30m',
        'red': '\033[31m',
        'green': '\033[32m',
        'yellow': '\033[33m',
        'blue': '\033[34m',
        'magenta': '\033[35m',
        'cyan': '\033[36m',
        'white': '\033[37m',
        'new': '\033[1m',
        'reset': '\033[0m'
    }

    formats = {
        'bold': '\033[1m',
        'faint': '\033[2m',
        'italic': '\033[3m',
        'blink': '\033[5m',
    }

    if format is not None:
        if color in colors:
            if format in formats:
                return f"{colors[color]}{formats[format]}{text}{colors['reset']}"
            else:
                return text
    else:
        if color in colors:
            return f"{colors[color]}{text}{colors['reset']}"
        else:
            return text

# Function to display the main banner
def main_banner():
    banner = """
    
    ██╗  ██╗ █████╗ ███████╗██╗  ██╗███╗   ███╗ █████╗ ████████╗███████╗
    ██║  ██║██╔══██╗██╔════╝██║  ██║████╗ ████║██╔══██╗╚══██╔══╝██╔════╝
    ███████║███████║███████╗███████║██╔████╔██║███████║   ██║   █████╗  
    ██╔══██║██╔══██║╚════██║██╔══██║██║╚██╔╝██║██╔══██║   ██║   ██╔══╝  
    ██║  ██║██║  ██║███████║██║  ██║██║ ╚═╝ ██║██║  ██║   ██║   ███████╗
    ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝

                                  v1.0
           
                           BY TOMAS ILLUMINATI             
"""

    # Print the banner with green color formatting
    print(colorize_text(banner, "green", "bold"))


# Function to print a line separator with the specified color
def separator(color):
    print(colorize_text("\n-----------------------------------------------------------------------------", color))

# Function to print a line separator with the specified color
def separator_2(color, size):
    print(colorize_text(f"\n{'-'*size}\n", color))


# Function to show the initial banner, including screen clearing
def init_banner():
    separator("cyan")  # Print a separator in cyan
    main_banner()  # Print the main banner
    separator("cyan")  # Print another separator in cyan
    