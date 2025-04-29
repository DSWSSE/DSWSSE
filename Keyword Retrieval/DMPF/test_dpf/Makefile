CC = gcc
CFLAGS = -Wall -Wextra -g -O2 -std=c99
LDFLAGS = -lcrypto -lssl -lm

# 源文件
SRCS = dpf_test.c dpf.c bitmap.c params.c
OBJS = $(SRCS:.c=.o)
TARGET = dpf_test

# 默认目标
all: $(TARGET)

# 链接程序
$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

# 编译源文件
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 清理构建文件
clean:
	rm -f $(OBJS) $(TARGET)

# 运行测试
test: $(TARGET)
	./$(TARGET)

.PHONY: all clean test
