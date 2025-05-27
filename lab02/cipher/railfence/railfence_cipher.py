class RailFenceCipher:
    def __init__(self):
        pass

    def rail_fence_encrypt(self, plain_text, num_rails):
        # Khởi tạo một danh sách các rails, mỗi rail là một danh sách rỗng
        rails = [[] for _ in range(num_rails)]

        rail_index = 0
        direction = 1  # 1: down, -1: up

        # Lặp qua từng ký tự trong plain_text và thêm vào các rails
        for char in plain_text:
            rails[rail_index].append(char)
            # Thay đổi hướng di chuyển (xuống hoặc lên)
            if rail_index == 0:
                direction = 1  # Di chuyển xuống
            elif rail_index == num_rails - 1:
                direction = -1  # Di chuyển lên
            rail_index += direction

        # Kết hợp tất cả các rails thành một chuỗi ciphertext
        cipher_text = "".join("".join(rail) for rail in rails)
        return cipher_text

    def rail_fence_decrypt(self, cipher_text, num_rails):
        # Khởi tạo danh sách chứa độ dài của các rails
        rail_lengths = [0] * num_rails
        rail_index = 0
        direction = 1

        # Tính toán số lượng ký tự trong mỗi rail
        for _ in range(len(cipher_text)):
            rail_lengths[rail_index] += 1
            if rail_index == 0:
                direction = 1
            elif rail_index == num_rails - 1:
                direction = -1
            rail_index += direction

        # Tạo một danh sách các rails
        rails = []
        start = 0
        for length in rail_lengths:
            rails.append(cipher_text[start:start + length])
            start += length

        # Khôi phục văn bản gốc từ các rails
        plain_text = []
        rail_index = 0
        direction = 1
        for _ in range(len(cipher_text)):
            plain_text.append(rails[rail_index][0])  # Thêm ký tự đầu tiên của rail vào plain_text
            rails[rail_index] = rails[rail_index][1:]  # Loại bỏ ký tự đã sử dụng
            if rail_index == 0:
                direction = 1
            elif rail_index == num_rails - 1:
                direction = -1
            rail_index += direction

        # Chuyển plain_text từ danh sách thành chuỗi
        return "".join(plain_text)
