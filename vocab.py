import collections.abc


def read_vocab(filename):
    vocab = Vocab()
    with open(filename, 'r') as stream:
        for line in stream:
            vocab.add(line.strip())
    return vocab


def save_vocab(vocab, stream):
    for imp in vocab:
        print(imp, file=stream)


class Vocab(collections.abc.MutableSet):
    """Set-like data structure that can change words into numbers and back."""
    def __init__(self):
        words = {"<unk>"}
        self.num_to_word = list(words)    
        self.word_to_num = {word:num for num, word in enumerate(self.num_to_word)}

    def add(self, word):
        if word in self: return
        num = len(self.num_to_word)
        self.num_to_word.append(word)
        self.word_to_num[word] = num

    def discard(self, word):
        raise NotImplementedError()
    def __contains__(self, word):
        return word in self.word_to_num
    def __len__(self):
        return len(self.num_to_word)
    def __iter__(self):
        return iter(self.num_to_word)

    def numberize(self, word):
        """Convert a word into a number."""
        if word in self.word_to_num:
            return self.word_to_num[word]
        else: 
            return self.word_to_num['<unk>']

    def denumberize(self, num):
        """Convert a number into a word."""
        return self.num_to_word[num]

