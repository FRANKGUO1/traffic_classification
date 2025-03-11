import torch.nn as nn
import torch.nn.functional as F


# 定义FlowPic CNN模型
class FlowPicCNN(nn.Module):
    def __init__(self, num_classes=4):
        super(FlowPicCNN, self).__init__()
        
        # CONV1: 16个5x5滤波器，步幅2，padding=2以保持'same'
        self.conv1 = nn.Conv2d(in_channels=1, out_channels=16, kernel_size=5, stride=2, padding=2)
        self.bn1 = nn.BatchNorm2d(16)
        
        # POOL1: 2x2最大池化
        self.pool = nn.MaxPool2d(kernel_size=2, stride=2)
        
        # CONV2: 32个3x3滤波器，步幅1，padding=1以保持'same'
        self.conv2 = nn.Conv2d(in_channels=16, out_channels=32, kernel_size=3, stride=1, padding=1)
        self.bn2 = nn.BatchNorm2d(32)
        
        # Dropout
        self.dropout1 = nn.Dropout(p=0.3)
        self.dropout2 = nn.Dropout(p=0.5)
        
        # 全连接层
        self.fc1 = nn.Linear(32 * 18 * 18, 128)  # 输入尺寸根据池化后计算
        self.fc2 = nn.Linear(128, num_classes)
    
    def forward(self, x):
        # x: [batch_size, 1, 148, 148]
        
        # CONV1 -> BatchNorm -> ReLU -> POOL1
        x = self.pool(F.relu(self.bn1(self.conv1(x))))  # 输出: [batch_size, 16, 75, 75]
        
        # CONV2 -> BatchNorm -> ReLU -> POOL2
        x = self.pool(F.relu(self.bn2(self.conv2(x))))  # 输出: [batch_size, 32, 37, 37]
        
        # Dropout
        x = self.dropout1(x)
        
        # Flatten
        x = x.view(x.size(0), -1)  # 输出: [batch_size, 37*37*32]
        
        # FC1 -> ReLU -> Dropout
        x = F.relu(self.fc1(x))  # 输出: [batch_size, 128]
        x = self.dropout2(x)
        
        # 输出层
        x = self.fc2(x)  # 输出: [batch_size, num_classes]
        
        return x


if __name__ == '__main__':
    model = FlowPicCNN(num_classes=5)
    print(model)
