import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from torch.utils.data import DataLoader, TensorDataset
import pandas as pd
import matplotlib.pyplot as plt

# 定义文件路径和类别标签
file_paths = {
    'class_1.csv': 1,
    'class_2.csv': 2,
    'class_3.csv': 3,
    'class_4.csv': 4
}

# 用于存储所有数据的列表
data_frames = []

# 读取每个文件并添加标签列
for file_path, label in file_paths.items():
    df = pd.read_csv(file_path)
    df['label'] = label
    data_frames.append(df)

# 合并所有数据框
data = pd.concat(data_frames, ignore_index=True)

# 显示前几行数据
print(data.head())

# 保存合并后的数据到新的CSV文件（可选）
data.to_csv('combined_data.csv', index=False)

# 特征和标签
X = data.drop(columns=['label']).values # 丢弃label这一列
y = data['label'].values - 1  # 将标签调整为 0-3

# 这里是将数据集第一次划分，(temp)占30%，训练集(train)占70%。random_state=42为设置随机种子。
X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=0.3, random_state=42)
# 这里是将temp进行第二次划分，验证集和测试集各占一半。
X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.5, random_state=42)

# 特征标准化
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_val = scaler.transform(X_val)
X_test = scaler.transform(X_test)

# 转换为张量
X_train = torch.tensor(X_train, dtype=torch.float32)
X_val = torch.tensor(X_val, dtype=torch.float32)
X_test = torch.tensor(X_test, dtype=torch.float32)
y_train = torch.tensor(y_train, dtype=torch.long)
y_val = torch.tensor(y_val, dtype=torch.long)
y_test = torch.tensor(y_test, dtype=torch.long)

# 创建数据加载器
train_dataset = TensorDataset(X_train, y_train)
val_dataset = TensorDataset(X_val, y_val)
test_dataset = TensorDataset(X_test, y_test)
# 每个批次的数据量
train_loader = DataLoader(train_dataset, batch_size=64, shuffle=True)
val_loader = DataLoader(val_dataset, batch_size=64, shuffle=False)
test_loader = DataLoader(test_dataset, batch_size=64, shuffle=False)

# 定义MLP模型
class MLP(nn.Module):
    def __init__(self, input_dim, num_classes):
        # 有三层线性层，三层非线性层
        super(MLP, self).__init__()
        # 全连接层，也是线性层
        self.fc1 = nn.Linear(input_dim, 128)
        # Dropout层用于防止过拟合，消除一些神经元
        self.dropout1 = nn.Dropout(0.5)
        self.fc2 = nn.Linear(128, 64)
        self.dropout2 = nn.Dropout(0.5)
        self.fc3 = nn.Linear(64, 32)
        self.dropout3 = nn.Dropout(0.5)
        self.output = nn.Linear(32, num_classes)  # 多分类输出

    def forward(self, x):
        x = torch.relu(self.fc1(x))
        x = self.dropout1(x)
        x = torch.relu(self.fc2(x))
        x = self.dropout2(x)
        x = torch.relu(self.fc3(x))
        x = self.dropout3(x)
        x = self.output(x)
        return x

# 初始化模型、损失函数和优化器
input_dim = X_train.shape[1]
num_classes = 4  # 假设是4类
model = MLP(input_dim, num_classes)
criterion = nn.CrossEntropyLoss()  # 交叉熵损失函数，计算损失率
optimizer = optim.Adam(model.parameters(), lr=0.001) # 优化器

train_losses = []
val_losses = []
train_accuracies = []
val_accuracies = []

# 训练模型
num_epochs = 50 # 50批次
best_val_loss = float('inf')

for epoch in range(num_epochs):
    # 训练阶段
    model.train()

    running_loss = 0.0
    correct_train = 0
    total_train = 0

    for X_batch, y_batch in train_loader:
        # 梯度置0
        optimizer.zero_grad()
        outputs = model(X_batch)
        loss = criterion(outputs, y_batch)
        # 损失率反向传播
        loss.backward()
        # 优化器优化
        optimizer.step()

        running_loss += loss.item() * X_batch.size(0)
        
        _, predicted = torch.max(outputs, 1)
        total_train += y_batch.size(0)
        correct_train += (predicted == y_batch).sum().item()

    train_loss = running_loss / total_train
    train_accuracy = correct_train / total_train
    
    # 验证阶段
    model.eval()
    val_loss = 0
    correct_val = 0
    total_val = 0
    with torch.no_grad():
        for X_batch, y_batch in val_loader:
            outputs = model(X_batch)
            loss = criterion(outputs, y_batch)
            val_loss += loss.item() * X_batch.size(0)

            _, predicted = torch.max(outputs, 1)
            total_val += y_batch.size(0)
            correct_val += (predicted == y_batch).sum().item()
    
    # val_loss /= len(val_loader)
    # print(f'Epoch {epoch+1}/{num_epochs}, Training Loss: {loss.item()}, Validation Loss: {val_loss}')
    val_loss = val_loss / total_val
    val_accuracy = correct_val / total_val
    
    train_losses.append(train_loss)
    val_losses.append(val_loss)
    train_accuracies.append(train_accuracy)
    val_accuracies.append(val_accuracy)
    
    print(f'Epoch {epoch+1}/{num_epochs}, '
          f'Training Loss: {train_loss:.4f}, Training Accuracy: {train_accuracy:.4f}, '
          f'Validation Loss: {val_loss:.4f}, Validation Accuracy: {val_accuracy:.4f}')

    # 保存最佳模型
    if val_loss < best_val_loss:
        best_val_loss = val_loss
        torch.save(model.state_dict(), 'best_model.pth')

print("Training complete!")


# 加载最佳模型
model.load_state_dict(torch.load('best_model.pth'))

# 评估模型
model.eval()
correct = 0
total = 0
with torch.no_grad():
    for X_batch, y_batch in test_loader:
        outputs = model(X_batch)
        _, predicted = torch.max(outputs, 1)
        total += y_batch.size(0)
        correct += (predicted == y_batch).sum().item()

test_accuracy = correct / total
print(f'Test Accuracy: {test_accuracy * 100:.2f}%')

# 绘制训练和验证的损失与准确率曲线
epochs = range(1, num_epochs + 1)

plt.figure(figsize=(12, 4))

plt.subplot(1, 2, 1)
plt.plot(epochs, train_losses, label='Train Loss')
plt.plot(epochs, val_losses, label='Validation Loss')
plt.xlabel('Epochs')
plt.ylabel('Loss')
plt.title('Loss over Epochs')
plt.legend()

plt.subplot(1, 2, 2)
plt.plot(epochs, train_accuracies, label='Train Accuracy')
plt.plot(epochs, val_accuracies, label='Validation Accuracy')
plt.xlabel('Epochs')
plt.ylabel('Accuracy')
plt.title('Accuracy over Epochs')
plt.legend()

plt.show()

"""
# 预测新数据
with torch.no_grad():
    outputs = model(X_test)
    _, predicted = torch.max(outputs, 1)
"""
