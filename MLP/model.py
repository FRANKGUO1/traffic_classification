import torch
import torch.nn as nn
import torch.nn.functional as F

class MLP(nn.Module):
    def __init__(self, input_size, num_classes):
        # 四层
        super(MLP, self).__init__()
        self.fc1 = nn.Linear(input_size, 256)
        self.bn1 = nn.BatchNorm1d(256)
        self.fc2 = nn.Linear(256, 128)
        self.bn2 = nn.BatchNorm1d(128)
        self.fc3 = nn.Linear(128, 64)
        self.bn3 = nn.BatchNorm1d(64)
        self.fc4 = nn.Linear(64, num_classes)
        self.dropout = nn.Dropout(0.5)

    def forward(self, x):
        x = nn.ReLU()(self.bn1(self.fc1(x)))
        x = self.dropout(x)
        x = nn.ReLU()(self.bn2(self.fc2(x)))
        x = self.dropout(x)
        x = nn.ReLU()(self.bn3(self.fc3(x)))
        x = self.dropout(x)
        x = self.fc4(x)
        return x



class My1DCNN(nn.Module):
    def __init__(self, num_features, num_classes):
        super(My1DCNN, self).__init__()

        self.conv1 = nn.Conv1d(in_channels=1, out_channels=32, kernel_size=1)
        self.pool1 = nn.MaxPool1d(kernel_size=1)
        self.drop1 = nn.Dropout(0.25)

        self.conv2 = nn.Conv1d(in_channels=32, out_channels=64, kernel_size=1)
        self.pool2 = nn.MaxPool1d(kernel_size=1)
        self.drop2 = nn.Dropout(0.25)

        self.conv3 = nn.Conv1d(in_channels=64, out_channels=128, kernel_size=1)
        self.pool3 = nn.MaxPool1d(kernel_size=1)
        self.drop3 = nn.Dropout(0.25)

        self.flatten = nn.Flatten()
        self.dense_input_size = self._get_dense_input_size(num_features)
        self.dense1 = nn.Linear(self.dense_input_size, 128)
        self.drop4 = nn.Dropout(0.5)
        self.output_layer = nn.Linear(128, num_classes)

    def _get_dense_input_size(self, num_features):
        # 创建一个假的输入来计算展平后的尺寸
        with torch.no_grad():
            x = torch.zeros(1, 1, num_features)
            x = self.conv1(x)
            x = self.pool1(x)
            x = self.conv2(x)
            x = self.pool2(x)
            x = self.conv3(x)
            x = self.pool3(x)
            x = self.flatten(x)
            return x.shape[1]

    def forward(self, x):
        x = self.conv1(x)
        x = torch.relu(x)
        x = self.pool1(x)
        x = self.drop1(x)

        x = self.conv2(x)
        x = torch.relu(x)
        x = self.pool2(x)
        x = self.drop2(x)

        x = self.conv3(x)
        x = torch.relu(x)
        x = self.pool3(x)
        x = self.drop3(x)

        x = self.flatten(x)
        x = self.dense1(x)
        x = torch.relu(x)
        x = self.drop4(x)
        x = self.output_layer(x)
        return x

