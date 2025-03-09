import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
import numpy as np
from model import FlowPicCNN


# 自定义数据集类
# 自定义数据集类
class FlowDataset(Dataset):
    def __init__(self, data):
        self.data = data  # 列表，每个元素是字典 {'image': ..., 'class': ...}

    def __len__(self):
        return len(self.data)
    
    def __getitem__(self, idx):
        image = self.data[idx]['image']  # (148, 148)
        image = torch.tensor(image, dtype=torch.float32).unsqueeze(0)  # 转换为 (1, 148, 148)
        
        # 获取 'class' 并映射为整数
        class_name = self.data[idx]['class']
        label = class_name  # 如果已经是整数，直接使用
        label = torch.tensor(label, dtype=torch.long)
        
        return image, label

# 加载数据
data_filename = 'your_file'  # 请替换为你的数据文件名前缀（不含 '_data.pt'）
data_path = f'{data_filename}_data.pt'
data = torch.load(data_path)
print(f"加载了 {len(data)} 个样本")

# 创建数据集和数据加载器
dataset = FlowDataset(data)
train_size = int(0.8 * len(dataset))  # 80% 训练，20% 验证
val_size = len(dataset) - train_size
train_dataset, val_dataset = torch.utils.data.random_split(dataset, [train_size, val_size])

train_loader = DataLoader(train_dataset, batch_size=32, shuffle=True)
val_loader = DataLoader(val_dataset, batch_size=32, shuffle=False)

# 初始化模型、损失函数和优化器
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
model = FlowPicCNN(num_classes=5).to(device)
criterion = nn.CrossEntropyLoss()
optimizer = optim.Adam(model.parameters(), lr=0.001)

# 训练函数
def train(model, train_loader, criterion, optimizer, device):
    model.train()
    running_loss = 0.0
    correct = 0
    total = 0
    
    for images, labels in train_loader:
        images, labels = images.to(device), labels.to(device)
        
        optimizer.zero_grad()
        outputs = model(images)
        loss = criterion(outputs, labels)
        loss.backward()
        optimizer.step()
        
        running_loss += loss.item()
        _, predicted = torch.max(outputs.data, 1)
        total += labels.size(0)
        correct += (predicted == labels).sum().item()
    
    epoch_loss = running_loss / len(train_loader)
    epoch_acc = 100 * correct / total
    return epoch_loss, epoch_acc

# 验证函数
def validate(model, val_loader, criterion, device):
    model.eval()
    running_loss = 0.0
    correct = 0
    total = 0
    
    with torch.no_grad():
        for images, labels in val_loader:
            images, labels = images.to(device), labels.to(device)
            outputs = model(images)
            loss = criterion(outputs, labels)
            
            running_loss += loss.item()
            _, predicted = torch.max(outputs.data, 1)
            total += labels.size(0)
            correct += (predicted == labels).sum().item()
    
    epoch_loss = running_loss / len(val_loader)
    epoch_acc = 100 * correct / total
    return epoch_loss, epoch_acc

# 训练循环
num_epochs = 20
for epoch in range(num_epochs):
    train_loss, train_acc = train(model, train_loader, criterion, optimizer, device)
    val_loss, val_acc = validate(model, val_loader, criterion, device)
    
    print(f"Epoch {epoch+1}/{num_epochs}:")
    print(f"Train Loss: {train_loss:.4f}, Train Acc: {train_acc:.2f}%")
    print(f"Val Loss: {val_loss:.4f}, Val Acc: {val_acc:.2f}%")

# 保存训练好的模型
torch.save(model.state_dict(), 'flowpic_cnn.pth')
print("模型已保存到 'flowpic_cnn.pth'")