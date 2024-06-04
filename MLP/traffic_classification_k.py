import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import KFold
from torch.utils.data import DataLoader, TensorDataset
import pandas as pd
from model import *



def train_model(lr, k=5):
    # 1. 读取CSV文件
    file_path = 'MLP/dataset/training_file10.csv'  # 替换为你的CSV文件路径
    data = pd.read_csv(file_path)

    # 2. 提取特征和标签
    X = data.iloc[:, :-1].values  # 除最后一列外的所有列为特征
    y = data.iloc[:, -1].values   # 最后一列为标签

    # 标签范围要在
    y = y - 1

    # 标准化
    scaler = StandardScaler()
    X = scaler.fit_transform(X)

    kf = KFold(n_splits=k, shuffle=True, random_state=42)

    fold = 0
    val_losses = []
    val_accuracies = []

    for train_index, val_index in kf.split(X):
        fold += 1
        print(f"Fold {fold}")

        X_train, X_val = X[train_index], X[val_index]
        y_train, y_val = y[train_index], y[val_index]

        # 转换为张量
        X_train = torch.tensor(X_train, dtype=torch.float32)
        X_val = torch.tensor(X_val, dtype=torch.float32)
        y_train = torch.tensor(y_train, dtype=torch.long)
        y_val = torch.tensor(y_val, dtype=torch.long)

        batch_size = 256

        # 创建数据加载器
        train_dataset = TensorDataset(X_train, y_train)
        val_dataset = TensorDataset(X_val, y_val)

        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
        val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)

        # 初始化模型、损失函数和优化器
        input_dim = X_train.shape[1]
        num_classes = 4  # 假设是4类

        model = MLP(input_dim, num_classes)
        criterion = nn.CrossEntropyLoss()  # 交叉熵损失函数，计算损失率
        optimizer = optim.Adam(model.parameters(), lr=lr, weight_decay=1e-5) # 优化器

        num_epochs = 40
        best_val_loss = float('inf')

        for _ in range(num_epochs):
            model.train()
            running_loss = 0.0
            correct_train = 0
            total_train = 0

            for X_batch, y_batch in train_loader:
                optimizer.zero_grad()
                outputs = model(X_batch)
                loss = criterion(outputs, y_batch)
                loss.backward()
                optimizer.step()

                running_loss += loss.item() * X_batch.size(0)
                _, predicted = torch.max(outputs, 1)
                total_train += y_batch.size(0)
                correct_train += (predicted == y_batch).sum().item()

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

            val_loss = val_loss / total_val
            val_accuracy = correct_val / total_val

            if val_loss < best_val_loss:
                best_val_loss = val_loss
                torch.save(model.state_dict(), f'best_model_fold_{fold}.pth')

        val_losses.append(val_loss)
        val_accuracies.append(val_accuracy)
        print(f'Fold {fold}, Validation Loss: {val_loss:.4f}, Validation Accuracy: {val_accuracy:.4f}')

    avg_val_loss = sum(val_losses) / k
    avg_val_accuracy = sum(val_accuracies) / k
    print(f'Average Validation Loss: {avg_val_loss:.4f}, Average Validation Accuracy: {avg_val_accuracy:.4f}')

train_model(0.001)



