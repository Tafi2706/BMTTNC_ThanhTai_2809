class PlayFairCipher:
    def __init__(self):
        pass

    def create_playfair_matrix(self, key):
        # Chuyển "J" thành "I" trong khóa
        key = key.replace("J", "I")
        key = key.upper()
        key_set = set(key)  # Tạo tập hợp các ký tự trong khóa
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        remaining_letters = [letter for letter in alphabet if letter not in key_set]

        matrix = list(key)  # Sử dụng list để lưu ký tự trong matrix
        for letter in remaining_letters:
            matrix.append(letter)
            if len(matrix) == 25:
                break

        # Tạo ma trận 5x5 từ khóa và các ký tự còn lại
        playfair_matrix = [matrix[i:i + 5] for i in range(0, len(matrix), 5)]
        return playfair_matrix

    def find_letter_coords(self, matrix, letter):
        for row in range(len(matrix)):
            for col in range(len(matrix[row])):
                if matrix[row][col] == letter:
                    return row, col

    def playfair_encrypt(self, plain_text, matrix):
        # Chuyển "J" thành "I" trong văn bản đầu vào
        plain_text = plain_text.replace("J", "I")
        plain_text = plain_text.upper()
        encrypted_text = ""

        # Đảm bảo plain_text có số ký tự chẵn (thêm 'X' nếu cần thiết)
        if len(plain_text) % 2 != 0:
            plain_text += "X"

        # Mã hóa theo từng cặp ký tự
        for i in range(0, len(plain_text), 2):
            pair = plain_text[i:i + 2]
            row1, col1 = self.find_letter_coords(matrix, pair[0])
            row2, col2 = self.find_letter_coords(matrix, pair[1])

            if row1 == row2:
                # Cùng hàng, dịch sang phải
                encrypted_text += matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5]
            elif col1 == col2:
                # Cùng cột, dịch xuống dưới
                encrypted_text += matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2]
            else:
                # Hình chữ nhật, thay đổi các cột
                encrypted_text += matrix[row1][col2] + matrix[row2][col1]

        return encrypted_text

    def playfair_decrypt(self, cipher_text, matrix):
        cipher_text = cipher_text.upper()
        decrypted_text = ""

        # Giải mã theo từng cặp ký tự
        for i in range(0, len(cipher_text), 2):
            pair = cipher_text[i:i + 2]
            row1, col1 = self.find_letter_coords(matrix, pair[0])
            row2, col2 = self.find_letter_coords(matrix, pair[1])

            if row1 == row2:
                # Cùng hàng, dịch sang trái
                decrypted_text += matrix[row1][(col1 - 1) % 5] + matrix[row2][(col2 - 1) % 5]
            elif col1 == col2:
                # Cùng cột, dịch lên trên
                decrypted_text += matrix[(row1 - 1) % 5][col1] + matrix[(row2 - 1) % 5][col2]
            else:
                # Hình chữ nhật, thay đổi các cột
                decrypted_text += matrix[row1][col2] + matrix[row2][col1]

        # Loại bỏ ký tự "X" nếu nó là ký tự được thêm vào cuối
        decrypted_text = decrypted_text.replace("X", "")

        return decrypted_text
