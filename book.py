import numpy as np
import matplotlib.pyplot as plt

# Define the parametric equations for the heart shape
t = np.linspace(0, 2 * np.pi, 1000)
x = 16 * np.sin(t)**3
y = 13 * np.cos(t) - 5 * np.cos(2 * t) - 2 * np.cos(3 * t) - np.cos(4 * t)

# Plotting the heart
plt.figure(figsize=(6, 6))
plt.plot(x, y, color='red', linewidth=2)

# Add title and labels
plt.title("Heart Shape", fontsize=16)
plt.axis('equal')  # Equal aspect ratio to maintain the shape
plt.axis('off')    # Hide axis
plt.show()
